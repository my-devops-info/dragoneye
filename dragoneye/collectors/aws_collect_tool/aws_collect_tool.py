import argparse
import concurrent
import copy
import os.path
import os
import re
from concurrent.futures._base import ALL_COMPLETED
from concurrent.futures.thread import ThreadPoolExecutor
import logging
import json
import time
from typing import List, Dict

import boto3
import urllib.parse
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError
from botocore.config import Config

from dragoneye.collect_requests.aws_collect_request import AwsCollectRequest, AwsAssumeRoleCollectRequest, AwsAccessKeyCollectRequest
from dragoneye.collectors.base_collect_tool.base_collect_tool import BaseCollect
from dragoneye.utils.misc_utils import get_dynamic_values_from_files, custom_serializer, make_directory, init_directory, load_yaml, snakecase, \
    elapsed_time

MAX_RETRIES = 3


class CloudMapperCollectException(Exception):
    def __init__(self, message, errors=None):
        super().__init__(message)
        if errors is None:
            errors = []
        self.errors = errors


class AwsCollectTool(BaseCollect):
    @classmethod
    @elapsed_time
    def collect(cls, collect_request: AwsCollectRequest) -> str:
        logging.getLogger("botocore").setLevel(logging.WARN)
        account_name = collect_request.account_name

        summary = []

        account_data_dir = init_directory(collect_request.output_path, account_name, collect_request.clean)

        default_region = cls._get_default_region()

        session = cls._get_session(collect_request)

        regions_filter = None
        if len(collect_request.regions_filter) > 0:
            regions_filter = collect_request.regions_filter.lower().split(",")
            # Force include of default region -- seems to be required
            if default_region not in regions_filter:
                regions_filter.append(default_region)

        print("* Getting region names", flush=True)
        ec2 = session.client("ec2")
        region_list = ec2.describe_regions()

        if regions_filter is not None:
            filtered_regions = [r for r in region_list["Regions"] if r["RegionName"] in regions_filter]
            region_list["Regions"] = filtered_regions

        with open(f"{account_data_dir}/describe-regions.json", "w+") as file:
            file.write(json.dumps(region_list, indent=4, sort_keys=True))

        print("* Creating directory for each region name", flush=True)
        region_dict_list: List[dict] = region_list["Regions"]

        for region in region_dict_list:
            make_directory(os.path.join(account_data_dir, region.get("RegionName", "Unknown")))

        # Services that will only be queried in the default_
        # TODO: Identify these from boto
        universal_services = [
            "iam",
            "route53",
            "route53domains",
            "s3",
            "cloudfront",
            "organizations",
        ]

        collect_commands = load_yaml(collect_request.commands_path)

        executor: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=10)
        dependable_commands = [command for command in collect_commands if command.get("Parameters", False)]
        non_dependable_commands = [command for command in collect_commands if not command.get("Parameters", False)]
        for region in region_dict_list:
            executor.submit(cls._collect_region_data, region, default_region, dependable_commands, non_dependable_commands, session,
                            universal_services, collect_request, account_data_dir, summary)
        executor.shutdown(True)

        # Print summary
        print("--------------------------------------------------------------------")
        failures = []
        for call_summary in summary:
            if "exception" in call_summary:
                failures.append(call_summary)

        print("Summary: {} APIs called. {} errors".format(len(summary), len(failures)))
        if len(failures) > 0:
            print("Failures:")
            for call_summary in failures:
                print(
                    "  {}.{}({}): {}".format(
                        call_summary["service"],
                        call_summary["action"],
                        call_summary["parameters"],
                        call_summary["exception"],
                    )
                )
            # Ensure errors can be detected
        return os.path.abspath(os.path.join(account_data_dir, '..'))

    @classmethod
    def test_authentication(cls, collect_request: AwsCollectRequest) -> bool:
        try:
            cls._get_session(collect_request)
            return True
        except Exception:
            return False

    @staticmethod
    def _get_identifier_from_parameter(parameter):
        if isinstance(parameter, list):
            identifier = parameter[0]
        else:
            identifier = parameter

        return identifier

    @staticmethod
    def _get_filename_from_parameter(parameter):
        if isinstance(parameter, list):
            if len(parameter) > 1:
                filename = parameter[1]
            elif isinstance(parameter[0], list):
                # For elbv2:describe-tags we need ResourceArns as a list like `[Arn]`
                # the yaml file specifies `[[.LoadBalancerArn]]` because just doing
                # `[.LoadBalancerArn]` presents other issues, so this extracts out the inner, inner value.
                # Similar issue for elb:describe-tags
                filename = parameter[0][0]
            else:
                filename = parameter[0]
        else:
            filename = parameter

        return urllib.parse.quote_plus(filename)

    @staticmethod
    def _call_function(outputfile, handler, method_to_call, parameters, check, summary):
        """
        Calls the AWS API function and downloads the data

        check: Value to check and repeat the call if it fails
        summary: Keeps tracks of failures
        """
        # TODO: Decorate this with rate limiters from
        # https://github.com/Netflix-Skunkworks/cloudaux/blob/master/cloudaux/aws/decorators.py

        data = {}
        if os.path.isfile(outputfile):
            # Data already collected, so skip
            print("  Response already collected at {}".format(outputfile), flush=True)
            return

        call_summary = {
            "service": handler.meta.service_model.service_name,
            "action": method_to_call,
            "parameters": parameters,
        }

        print("  Making call for {}".format(outputfile), flush=True)
        try:
            for retries in range(MAX_RETRIES):
                if handler.can_paginate(method_to_call):
                    paginator = handler.get_paginator(method_to_call)
                    page_iterator = paginator.paginate(**parameters)
                    for response in page_iterator:
                        if not data:
                            data = response

                        else:
                            print("  ...paginating {}".format(outputfile), flush=True)
                            for k in data:
                                if isinstance(data[k], list):
                                    data[k].extend(response[k])
                else:
                    function = getattr(handler, method_to_call)
                    data = function(**parameters)

                if check is not None:
                    if data[check[0]["Name"]] == check[0]["Value"]:
                        continue
                    if retries == MAX_RETRIES - 1:
                        raise Exception(
                            "Check value {} never set as {} in response".format(
                                check["Name"], check["Value"]
                            )
                        )
                    print("  Sleeping and retrying")
                    time.sleep(3)
                else:
                    break

        except ClientError as ex:
            if "NoSuchBucketPolicy" in str(ex):
                # This error occurs when you try to get the bucket policy for a bucket that has no bucket policy, so this can be ignored.
                print("  - No bucket policy")
            elif "NoSuchPublicAccessBlockConfiguration" in str(ex):
                # This error occurs when you try to get the account Public Access Block policy for an account that has none, so this can be ignored.
                print("  - No public access block set")
            elif (
                    "ServerSideEncryptionConfigurationNotFoundError" in str(ex)
                    and call_summary["service"] == "s3"
                    and call_summary["action"] == "get_bucket_encryption"
            ):
                print("  - No encryption set")
            elif (
                    "NoSuchEntity" in str(ex)
                    and call_summary["action"] == "get_account_password_policy"
            ):
                print("  - No password policy set")
            elif (
                    "AccessDeniedException" in str(ex)
                    and call_summary["service"] == "organizations"
                    and call_summary["action"] == "list_accounts"
            ):
                print("  - Denied, which likely means this is not the organization root")
            elif (
                    "RepositoryPolicyNotFoundException" in str(ex)
                    and call_summary["service"] == "ecr"
                    and call_summary["action"] == "get_repository_policy"
            ):
                print("  - No policy exists")
            elif (
                    "ResourceNotFoundException" in str(ex)
                    and call_summary["service"] == "lambda"
                    and call_summary["action"] == "get_policy"
            ):
                print("  - No policy exists")
            elif (
                    "AccessDeniedException" in str(ex)
                    and call_summary["service"] == "kms"
                    and call_summary["action"] == "list_key_policies"
            ):
                print("  - Denied, which should mean this KMS has restricted access")
            elif (
                    "AccessDeniedException" in str(ex)
                    and call_summary["service"] == "kms"
                    and call_summary["action"] == "list_grants"
            ):
                print("  - Denied, which should mean this KMS has restricted access")
            elif (
                    "AccessDeniedException" in str(ex)
                    and call_summary["service"] == "kms"
                    and call_summary["action"] == "get_key_policy"
            ):
                print("  - Denied, which should mean this KMS has restricted access")
            elif (
                    "AccessDeniedException" in str(ex)
                    and call_summary["service"] == "kms"
                    and call_summary["action"] == "get_key_rotation_status"
            ):
                print("  - Denied, which should mean this KMS has restricted access")
            elif "AWSOrganizationsNotInUseException" in str(ex):
                print(' - Your account is not a member of an organization.')
            else:
                print(f"ClientError {retries}: {ex}", flush=True)
                call_summary["exception"] = ex
        except EndpointConnectionError as ex:
            print("EndpointConnectionError: {}".format(ex), flush=True)
            call_summary["exception"] = ex
        except Exception as ex:
            print("Exception: {}".format(ex), flush=True)
            call_summary["exception"] = ex

        # Remove unused values
        if data is not None:
            data.pop("ResponseMetadata", None)
            data.pop("Marker", None)
            data.pop("IsTruncated", None)

        if data is not None:
            with open(outputfile, "w+") as file:
                file.write(
                    json.dumps(data, indent=4, sort_keys=True, default=custom_serializer)
                )

        print("finished call for {}".format(outputfile), flush=True)
        summary.append(call_summary)

    @classmethod
    def _collect_command_data(cls, region, default_region, runner, session, universal_services, arguments, account_dir, summary):
        executor: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=20)
        tasks = []
        region = copy.deepcopy(region)
        runner = copy.deepcopy(runner)
        print(
            "* Getting {}:{}:{} info".format(region["RegionName"], runner["Service"], runner["Request"]),
            flush=True,
        )
        # Only call universal services in default region
        if runner["Service"] in universal_services:
            if region["RegionName"] != default_region:
                return
        elif runner["Service"] != 'eks' and region["RegionName"] not in session.get_available_regions(runner["Service"]):
            print("Skipping region {}, as {} does not exist there"
                  .format(region["RegionName"], runner["Service"]))
            return
        handler = session.client(
            runner["Service"], region_name=region["RegionName"],
            config=Config(retries={'max_attempts': arguments.max_attempts, 'mode': 'standard'}, max_pool_connections=arguments.max_pool_connections)
        )

        filepath = os.path.join(account_dir, region["RegionName"], f'{runner["Service"]}--{runner["Request"]}')

        method_to_call = snakecase(runner["Request"])
        param_groups = []
        parameter_keys = set()
        for parameter in runner.get("Parameters", []):
            name = parameter["Name"]
            value = parameter["Value"]
            is_dynamic = "|" in value
            parameter_keys.add(name)
            if not is_dynamic:
                param_groups = cls._fill_simple_params(param_groups, name, value)
            else:
                group = parameter.get("Group", False)
                param_groups = cls._fill_dynamic_params(param_groups, name, value, group, account_dir, region)

        if runner.get("Parameters"):
            make_directory(filepath)
            for param_group in param_groups:
                if set(param_group.keys()) != parameter_keys:
                    continue
                file_name = urllib.parse.quote_plus('_'.join([f'{k}-{v}' for k, v in param_group.items()]))
                output_file = f"{filepath}/{file_name}.json"
                tasks.append(executor.submit(cls._call_function,
                                             output_file,
                                             handler,
                                             method_to_call,
                                             param_group,
                                             runner.get("Check", None),
                                             summary,
                                             ))
        else:
            filepath = filepath + ".json"
            tasks.append(executor.submit(cls._call_function,
                                         filepath,
                                         handler,
                                         method_to_call,
                                         {},
                                         runner.get("Check", None),
                                         summary,
                                         ))
        concurrent.futures.wait(tasks, timeout=arguments.command_timeout, return_when=ALL_COMPLETED)
        timeout_tasks = [task for task in tasks if task.running()]
        if timeout_tasks:
            logging.exception('timeout command {}'.format(runner))
        for timeout_task in timeout_tasks:
            timeout_task.cancel()

    @classmethod
    def _collect_region_data(cls, region, default_region, dependable_commands, non_dependable_commands, session, universal_services, arguments,
                             account_dir, summary):
        executor: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=20)
        for command in non_dependable_commands:
            executor.submit(cls._collect_command_data, region, default_region, command, session, universal_services, arguments, account_dir, summary)
        executor.shutdown(True)

        for command in dependable_commands:
            cls._collect_command_data(region, default_region, command, session, universal_services, arguments, account_dir, summary)

    @classmethod
    def _get_session(cls, arguments: AwsCollectRequest):
        if isinstance(arguments, AwsAssumeRoleCollectRequest):
            return cls._get_session_by_assume_role(arguments.account_id, arguments.role_name, arguments.external_id, arguments.duration_session_time)
        elif isinstance(arguments, AwsAccessKeyCollectRequest):
            return cls._get_session_by_access_key(arguments, cls._get_default_region())
        else:
            raise Exception(f'Unknown arguments type. Got: {type(arguments).__name__}, '
                            f'expected: ({AwsAssumeRoleCollectRequest.__name__}, {AwsAccessKeyCollectRequest.__name__})')

    @classmethod
    def _get_session_by_access_key(cls, arguments: AwsAccessKeyCollectRequest, default_region):
        session_data = {"region_name": default_region}

        if arguments.profile_name:
            session_data["profile_name"] = arguments.profile_name

        session = boto3.Session(**session_data)
        cls._assert_session(session)

        return session

    @classmethod
    def _get_session_by_assume_role(cls, account_id, role_name, external_id, session_duration):
        role_arn = "arn:aws:iam::" + account_id + ":role/" + role_name
        role_session_name = "cloudmapperSession"
        print('will try to assume role using ARN: {} and external id {} for account {}'.format(role_arn, external_id, account_id))
        client = boto3.client('sts')
        response = client.assume_role(RoleArn=role_arn,
                                      RoleSessionName=role_session_name,
                                      DurationSeconds=session_duration,
                                      ExternalId=external_id)
        credentials = response['Credentials']
        session = boto3.Session(aws_access_key_id=credentials['AccessKeyId'],
                                aws_secret_access_key=credentials['SecretAccessKey'],
                                aws_session_token=credentials['SessionToken'],
                                region_name=cls._get_default_region())

        cls._assert_session(session)
        return session

    @staticmethod
    def _get_default_region() -> str:
        default_region = os.environ.get("AWS_REGION", "us-east-1")
        if 'gov-' in default_region:
            default_region = 'us-gov-west-1'
        elif 'cn-' in default_region:
            default_region = 'cn-north-1'
        else:
            default_region = 'us-east-1'
        return default_region

    @staticmethod
    def _get_call_parameters(call_parameters: dict, parameters_def: list) -> List[dict]:
        group_param = {}
        for parameter_def in parameters_def:
            group_param[parameter_def['Name']] = parameter_def.get('Group', False)

        params = []
        keys = list(call_parameters.keys())

        if len(call_parameters) == 1:
            for key in keys:
                for value in call_parameters[key]:
                    params.append({key: value})

        elif len(call_parameters) == 2:
            for value1 in call_parameters[keys[0]]:
                if group_param[keys[1]]:
                    params.append({keys[0]: value1, keys[1]: call_parameters[keys[1]]})
                else:
                    for value2 in call_parameters[keys[1]]:
                        params.append({keys[0]: value1, keys[1]: value2})

        return params

    @staticmethod
    def _assert_session(session):
        sts = session.client("sts")
        try:
            sts.get_caller_identity()
        except ClientError as ex:
            if "InvalidClientTokenId" in str(ex):
                raise CloudMapperCollectException('sts.get_caller_identity failed with InvalidClientTokenId. '
                                                  'Likely cause is no AWS credentials are set', ex)
            raise CloudMapperCollectException('Unknown exception when trying to call sts.get_caller_identity: {}'.format(ex), ex)

        iam = session.client("iam")
        try:
            iam.get_user(UserName="CloudMapper")
        except ClientError as ex:
            if "InvalidClientTokenId" in str(ex):
                raise CloudMapperCollectException(
                    "AWS doesn't allow you to make IAM calls from a session without MFA, and the collect command gathers IAM data.  "
                    "Please use MFA or don't use a session. With aws-vault, specify `--no-session` on your `exec`.", ex)
            if "NoSuchEntity" in str(ex):
                # Ignore, we're just testing that our credentials work
                pass
            else:
                raise CloudMapperCollectException('Ensure your credentials are valid', ex)
        except NoCredentialsError as ex:
            raise CloudMapperCollectException("No AWS credentials configured.", ex)

    @staticmethod
    def _fill_simple_params(param_groups, name, value):
        if not param_groups:
            param_groups = [{name: value}]
            return param_groups
        else:
            for param_group in param_groups:
                param_group[name] = value
            return param_groups

    @staticmethod
    def _fill_dynamic_params(param_groups: List[dict],
                             name: str,
                             value: str,
                             group: bool,
                             account_dir: str,
                             region: Dict[str, str]) -> List[dict]:
        depends_on_keys = re.findall(r'\{\{(.*)\}\}', value) or []
        region_account_dir = os.path.join(account_dir, region['RegionName'])
        if not param_groups and depends_on_keys:
            return param_groups
        if not param_groups and not depends_on_keys:
            values = get_dynamic_values_from_files(value, region_account_dir)
            if group:
                param_groups.append({name: values})
                return param_groups
            else:
                for val in values:
                    param_groups.append({name: val})
                return param_groups
        cached_values = {}
        result_param_groups = []
        for param_group in param_groups:
            real_value = value
            for key in depends_on_keys:
                real_value = real_value.replace(f'{{{{{key}}}}}', param_group[key])
            cached_values[real_value] = cached_values.get(real_value, get_dynamic_values_from_files(real_value, region_account_dir))
            if group:
                param_group[name] = cached_values[real_value]
                result_param_groups.append(param_group)
            else:
                for cached_value in cached_values[real_value]:
                    clone_param_group = copy.deepcopy(param_group)
                    clone_param_group[name] = cached_value
                    result_param_groups.append(clone_param_group)
        return result_param_groups

    @classmethod
    def add_parser_args(cls, parser):
        sub = parser.add_subparsers(dest='authentication-technique', required=True)

        collect_by_assume_role = sub.add_parser('assume-role', help='Collect data by assuming a role')
        collect_by_access_key = sub.add_parser('access-key', help='Collect data using an access-key')

        cls._add_parser_arguments_for_assume_role(collect_by_assume_role)
        cls._add_parser_arguments_for_access_key(collect_by_access_key)

    @staticmethod
    def _add_parser_arguments_for_assume_role(parser):
        parser.add_argument(
            "--account",
            help="Account to collect from",
            required=False,
            type=str,
            default='default',
            dest="account_name",
        )
        parser.add_argument(
            "--clean",
            help="Remove any existing data for the account before gathering",
            action="store_true",
        )
        parser.add_argument(
            "--max-attempts",
            help="Override Botocore config max_attempts (default 4)",
            required=False,
            type=int,
            dest="max_attempts",
            default=4
        )
        parser.add_argument(
            "--account-id",
            help="The account id to collect data from",
            required=True,
            type=str,
            dest="account_id"
        )
        parser.add_argument(
            "--external-id",
            help="The assume role external id",
            required=True,
            type=str,
            dest="external_id"
        )
        parser.add_argument(
            "--role-name",
            help="The AssumeRole role name",
            required=True,
            type=str,
            dest="role_name"
        )
        parser.add_argument(
            "--duration-session-time",
            help="the duration for the generated credential",
            required=False,
            type=int,
            dest="duration_session_time",
            default=3600
        )
        parser.add_argument(
            "--regions",
            help="Filter and query AWS only for the given regions (CSV)",
            required=False,
            type=str,
            dest="regions_filter",
            default=""
        )
        parser.add_argument(
            "--max-pool-connections",
            help="Override Botocore config max_pool_connections (default 10)",
            required=False,
            type=int,
            dest="max_pool_connections",
            default=10
        )
        parser.add_argument(
            "--command-timeout",
            help="The number of seconds before terminating a command (default 600)",
            required=False,
            type=int,
            dest="command_timeout",
            default=600
        )
        parser.add_argument(
            '-hidden-arg',
            dest='assume_role',
            default=True,
            help=argparse.SUPPRESS
        )
        parser.add_argument(
            '--output-path',
            dest='output_path',
            required=False,
            type=str,
            default=os.getcwd(),
            help='The path in which the collect results will be saved on. Defaults to current working directory.'
        )
        parser.add_argument(
            '--commands-path',
            dest='commands_path',
            required=True,
            type=str,
            help='The file path to the yaml file that contains all the commands to run'
        )

    @staticmethod
    def _add_parser_arguments_for_access_key(parser):
        parser.add_argument(
            "--account",
            help="Account to collect from",
            required=False,
            type=str,
            default='default',
            dest="account_name",
        )
        parser.add_argument(
            "--profile",
            help="AWS profile name",
            required=False,
            type=str,
            dest="profile_name",
        )
        parser.add_argument(
            "--clean",
            help="Remove any existing data for the account before gathering",
            action="store_true",
        )
        parser.add_argument(
            "--max-attempts",
            help="Override Botocore config max_attempts (default 4)",
            required=False,
            type=int,
            dest="max_attempts",
            default=4
        )
        parser.add_argument(
            "--regions",
            help="Filter and query AWS only for the given regions (CSV)",
            required=False,
            type=str,
            dest="regions_filter",
            default=""
        )
        parser.add_argument(
            "--max-pool-connections",
            help="Override Botocore config max_pool_connections (default 10)",
            required=False,
            type=int,
            dest="max_pool_connections",
            default=10
        )
        parser.add_argument(
            "--command-timeout",
            help="The number of seconds before terminating a command (default 600)",
            required=False,
            type=int,
            dest="command_timeout",
            default=600
        )
        parser.add_argument(
            '-hidden-arg',
            dest='assume_role',
            default=False,
            help=argparse.SUPPRESS
        )
        parser.add_argument(
            '--output-path',
            dest='output_path',
            required=False,
            type=str,
            default=os.getcwd(),
            help='The path in which the collect results will be saved on. Defaults to current working directory.'
        )
        parser.add_argument(
            '--commands-path',
            dest='commands_path',
            required=True,
            type=str,
            help='The file path to the yaml file that contains all the commands to run'
        )
        parser.add_argument(
            "--duration-session-time",
            help="the duration for the generated credential",
            required=False,
            type=int,
            dest="duration_session_time",
            default=3600
        )

    @staticmethod
    def convert_args_to_request(args):
        if args.assume_role:
            return AwsAssumeRoleCollectRequest(account_id=args.account_id,
                                               account_name=args.account_name,
                                               external_id=args.external_id,
                                               role_name=args.role_name,
                                               clean=args.clean,
                                               regions_filter=args.regions_filter,
                                               duration_session_time=args.duration_session_time,
                                               max_attempts=args.max_attempts,
                                               max_pool_connections=args.max_pool_connections,
                                               command_timeout=args.command_timeout,
                                               output_path=args.output_path,
                                               commands_path=args.commands_path)
        else:
            return AwsAccessKeyCollectRequest(account_name=args.account_name,
                                              profile_name=args.profile_name,
                                              max_attempts=args.max_attempts,
                                              clean=args.clean,
                                              regions_filter=args.regions_filter,
                                              duration_session_time=args.duration_session_time,
                                              max_pool_connections=args.max_pool_connections,
                                              command_timeout=args.command_timeout,
                                              output_path=args.output_path,
                                              commands_path=args.commands_path)
