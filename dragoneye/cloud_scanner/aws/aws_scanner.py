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

import urllib.parse
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError
from botocore.config import Config

from dragoneye.cloud_scanner.aws.aws_scan_request import AwsCredentials, AwsCloudScanSettings
from dragoneye.cloud_scanner.aws.aws_session_factory import AwsSessionFactory
from dragoneye.cloud_scanner.base_cloud_scanner import BaseCloudScanner, CloudCredentials
from dragoneye.dragoneye_exception import DragoneyeException
from dragoneye.utils.misc_utils import get_dynamic_values_from_files, custom_serializer, make_directory, init_directory, load_yaml, snakecase, \
    elapsed_time

MAX_RETRIES = 3


class AwsScanner(BaseCloudScanner):

    def test_connectivity(self, cloud_credentials: CloudCredentials):
        aws_cloud_credentials: AwsCredentials = cloud_credentials
        try:
            AwsSessionFactory.get_session(aws_cloud_credentials)
            return True
        except:
            return False

    @classmethod
    @elapsed_time
    def collect(cls, boto_session, scan_settings: AwsCloudScanSettings) -> str:
        logging.getLogger("botocore").setLevel(logging.WARN)
        account_name = scan_settings.account_name
        session = boto_session
        account_data_dir = init_directory(scan_settings.output_path, account_name, scan_settings.clean)
        summary = []

        regions_filter = None
        if len(scan_settings.regions_filter) > 0:
            regions_filter = scan_settings.regions_filter.lower().split(",")
            # Force include of default region -- seems to be required
            if scan_settings.default_region not in regions_filter:
                regions_filter.append(scan_settings.default_region)

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

        collect_commands = load_yaml(scan_settings.commands_path)

        executor: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=10)
        dependable_commands = [command for command in collect_commands if command.get("Parameters", False)]
        non_dependable_commands = [command for command in collect_commands if not command.get("Parameters", False)]
        for region in region_dict_list:
            executor.submit(cls._collect_region_data, region, dependable_commands, non_dependable_commands, session,
                            universal_services, scan_settings, account_data_dir, summary)
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
    def _collect_command_data(cls, region, runner, session, universal_services, arguments, account_dir, summary):
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
            if region["RegionName"] != arguments.default_region:
                return
        elif runner["Service"] != 'eks' and region["RegionName"] not in session.get_available_regions(runner["Service"]):
            print("Skipping region {}, as {} does not exist there"
                  .format(region["RegionName"], runner["Service"]))
            return
        handler = session.client(
            runner["Service"], region_name=region["RegionName"],
            config=Config(retries={'max_attempts': arguments.max_attempts, 'mode': 'standard'},
                          max_pool_connections=arguments.max_pool_connections)
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
    def _collect_region_data(cls, region, dependable_commands, non_dependable_commands, session, universal_services, arguments,
                             account_dir, summary):
        executor: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=20)
        for command in non_dependable_commands:
            executor.submit(cls._collect_command_data, region, command, session, universal_services, arguments, account_dir, summary)
        executor.shutdown(True)

        for command in dependable_commands:
            cls._collect_command_data(region, command, session, universal_services, arguments, account_dir, summary)

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
                raise DragoneyeException('sts.get_caller_identity failed with InvalidClientTokenId. '
                                         'Likely cause is no AWS credentials are set', ex)
            raise DragoneyeException('Unknown exception when trying to call sts.get_caller_identity: {}'.format(ex), ex)

        iam = session.client("iam")
        try:
            iam.get_user(UserName="CloudMapper")
        except ClientError as ex:
            if "InvalidClientTokenId" in str(ex):
                raise DragoneyeException(
                    "AWS doesn't allow you to make IAM calls from a session without MFA, and the collect command gathers IAM data.  "
                    "Please use MFA or don't use a session. With aws-vault, specify `--no-session` on your `exec`.", ex)
            if "NoSuchEntity" in str(ex):
                # Ignore, we're just testing that our credentials work
                pass
            else:
                raise DragoneyeException('Ensure your credentials are valid', ex)
        except NoCredentialsError as ex:
            raise DragoneyeException("No AWS credentials configured.", ex)

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
