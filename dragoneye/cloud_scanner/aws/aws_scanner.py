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
from typing import List, Dict, Optional

import urllib.parse
from botocore.exceptions import ClientError, EndpointConnectionError
from botocore.config import Config

from dragoneye.cloud_scanner.aws.aws_scan_request import AwsCloudScanSettings
from dragoneye.cloud_scanner.base_cloud_scanner import BaseCloudScanner
from dragoneye.utils.app_logger import logger
from dragoneye.utils.misc_utils import get_dynamic_values_from_files, custom_serializer, make_directory, init_directory, load_yaml, snakecase, \
    elapsed_time

MAX_RETRIES = 3
MAX_WORKER = 10


class AwsScanner(BaseCloudScanner):

    def __init__(self, session, settings: AwsCloudScanSettings):
        self.session = session
        self.settings = settings
        # Services that will only be queried in the default region
        # TODO: Identify these from boto
        self.universal_services = [
            "iam",
            "route53",
            "route53domains",
            "s3",
            "cloudfront",
            "organizations",
        ]
        logging.getLogger("botocore").setLevel(logging.WARN)

    @elapsed_time('Scanning AWS live environment took {} seconds')
    def scan(self) -> str:
        account_data_dir = init_directory(self.settings.output_path, self.settings.account_name, self.settings.clean)
        region_dict_list = self._create_regions_file_structure(account_data_dir)

        summary = []
        executor: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=MAX_WORKER)

        for region in region_dict_list:
            executor.submit(self._scan_region_data, region, account_data_dir, summary)
        executor.shutdown(True)

        self._print_summary(summary)

        return os.path.abspath(os.path.join(account_data_dir, '..'))

    def _create_regions_file_structure(self, base_path: str):
        region_list = self._get_region_list()

        with open(f"{base_path}/describe-regions.json", "w+") as file:
            file.write(json.dumps(region_list, indent=4, sort_keys=True))

        logger.info("* Creating directory for each region name")
        region_dict_list: List[dict] = region_list["Regions"]

        for region in region_dict_list:
            make_directory(os.path.join(base_path, region.get("RegionName", "Unknown")))

        return region_dict_list

    def _get_region_list(self):
        regions_filter = None
        if len(self.settings.regions_filter) > 0:
            regions_filter = self.settings.regions_filter.lower().split(",")
            # Force include of default region -- seems to be required
            if self.settings.default_region not in regions_filter:
                regions_filter.append(self.settings.default_region)

        logger.info("* Getting region names")
        ec2 = self.session.client("ec2")
        region_list = ec2.describe_regions()

        if regions_filter is not None:
            filtered_regions = [r for r in region_list["Regions"] if r["RegionName"] in regions_filter]
            region_list["Regions"] = filtered_regions

        return region_list

    @staticmethod
    def _print_summary(summary):
        logger.info("--------------------------------------------------------------------")
        failures = []
        for call_summary in summary:
            if "exception" in call_summary:
                failures.append(call_summary)

        logger.info("Summary: {} APIs called. {} errors".format(len(summary), len(failures)))
        if len(failures) > 0:
            logger.warning("Failures:")
            for call_summary in failures:
                logger.warning(
                    "  {}.{}({}): {}".format(
                        call_summary["service"],
                        call_summary["action"],
                        call_summary["parameters"],
                        call_summary["exception"],
                    )
                )

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
    def _get_and_save_data(output_file, handler, method_to_call, parameters, checks, summary):
        """
        Calls the AWS API function and downloads the data

        check: Value to check and repeat the call if it fails
        summary: Keeps tracks of failures
        """
        # TODO: Decorate this with rate limiters from
        # https://github.com/Netflix-Skunkworks/cloudaux/blob/master/cloudaux/aws/decorators.py
        if os.path.isfile(output_file):
            # Data already scanned, so skip
            logger.warning("  Response already present at {}".format(output_file))
            return

        call_summary = {
            "service": handler.meta.service_model.service_name,
            "action": method_to_call,
            "parameters": parameters,
        }

        data = AwsScanner._get_data(output_file, handler, method_to_call, parameters, checks, call_summary)
        AwsScanner._remove_unused_values(data)
        AwsScanner._save_results_to_file(output_file, data)

        logger.info("finished call for {}".format(output_file))
        summary.append(call_summary)

    @staticmethod
    def _get_data(output_file, handler, method_to_call, parameters, checks, call_summary):
        logger.info("  Making call for {}".format(output_file))
        try:
            for retries in range(MAX_RETRIES):
                data = AwsScanner._call_boto_function(output_file, handler, method_to_call, parameters)
                if not checks or AwsScanner._is_data_passing_check(data, checks):
                    pass
                elif retries == MAX_RETRIES - 1:
                    raise Exception(
                        "One of the following checks has repeatedly failed: {}".format(
                            ', '.join(f'{check["Name"]}={check["Value"]}' for check in checks)
                        )
                    )
                else:
                    logger.info("  Sleeping and retrying")
                    time.sleep(3)

        except ClientError as ex:
            if "NoSuchBucketPolicy" in str(ex):
                # This error occurs when you try to get the bucket policy for a bucket that has no bucket policy, so this can be ignored.
                logger.warning("  - No bucket policy")
            elif "NoSuchPublicAccessBlockConfiguration" in str(ex):
                # This error occurs when you try to get the account Public Access Block policy for an account that has none, so this can be ignored.
                logger.warning("  - No public access block set")
            elif (
                    "ServerSideEncryptionConfigurationNotFoundError" in str(ex)
                    and call_summary["service"] == "s3"
                    and call_summary["action"] == "get_bucket_encryption"
            ):
                logger.warning("  - No encryption set")
            elif (
                    "NoSuchEntity" in str(ex)
                    and call_summary["action"] == "get_account_password_policy"
            ):
                logger.warning("  - No password policy set")
            elif (
                    "AccessDeniedException" in str(ex)
                    and call_summary["service"] == "organizations"
                    and call_summary["action"] == "list_accounts"
            ):
                logger.warning("  - Denied, which likely means this is not the organization root")
            elif (
                    "RepositoryPolicyNotFoundException" in str(ex)
                    and call_summary["service"] == "ecr"
                    and call_summary["action"] == "get_repository_policy"
            ):
                logger.warning("  - No policy exists")
            elif (
                    "ResourceNotFoundException" in str(ex)
                    and call_summary["service"] == "lambda"
                    and call_summary["action"] == "get_policy"
            ):
                logger.warning("  - No policy exists")
            elif (
                    "AccessDeniedException" in str(ex)
                    and call_summary["service"] == "kms"
                    and call_summary["action"] == "list_key_policies"
            ):
                logger.warning("  - Denied, which should mean this KMS has restricted access")
            elif (
                    "AccessDeniedException" in str(ex)
                    and call_summary["service"] == "kms"
                    and call_summary["action"] == "list_grants"
            ):
                logger.warning("  - Denied, which should mean this KMS has restricted access")
            elif (
                    "AccessDeniedException" in str(ex)
                    and call_summary["service"] == "kms"
                    and call_summary["action"] == "get_key_policy"
            ):
                logger.warning("  - Denied, which should mean this KMS has restricted access")
            elif (
                    "AccessDeniedException" in str(ex)
                    and call_summary["service"] == "kms"
                    and call_summary["action"] == "get_key_rotation_status"
            ):
                logger.warning("  - Denied, which should mean this KMS has restricted access")
            elif "AWSOrganizationsNotInUseException" in str(ex):
                logger.warning(' - Your account is not a member of an organization.')
            else:
                logger.warning(f"ClientError {retries}: {ex}")
                call_summary["exception"] = ex
        except EndpointConnectionError as ex:
            logger.warning("EndpointConnectionError: {}".format(ex))
            call_summary["exception"] = ex
        except Exception as ex:
            logger.warning("Exception: {}".format(ex))
            call_summary["exception"] = ex

        return data

    @staticmethod
    def _call_boto_function(output_file, handler, method_to_call, parameters):
        data = {}
        if handler.can_paginate(method_to_call):
            paginator = handler.get_paginator(method_to_call)
            page_iterator = paginator.paginate(**parameters)
            for response in page_iterator:
                if not data:
                    data = response

                else:
                    logger.info("  ...paginating {}".format(output_file))
                    for k in data:
                        if isinstance(data[k], list):
                            data[k].extend(response[k])
        else:
            function = getattr(handler, method_to_call)
            data = function(**parameters)

        return data

    @staticmethod
    def _is_data_passing_check(data: dict, checks: Optional[dict]) -> bool:
        if checks:
            for check in checks:
                if data[check["Name"]] == check["Value"]:
                    pass
                else:
                    return False
        return True

    @staticmethod
    def _remove_unused_values(data: dict) -> None:
        if data is not None:
            data.pop("ResponseMetadata", None)
            data.pop("Marker", None)
            data.pop("IsTruncated", None)

    @staticmethod
    def _save_results_to_file(output_file: str, data: Optional[Dict]) -> None:
        if data is not None:
            with open(output_file, "w+") as file:
                file.write(
                    json.dumps(data, indent=4, sort_keys=True, default=custom_serializer)
                )

    def _run_scan_commands(self, region, runner, account_dir, summary):
        executor: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=20)
        tasks = []
        region = copy.deepcopy(region)
        runner = copy.deepcopy(runner)
        logger.info(
            "* Getting {}:{}:{} info".format(region["RegionName"], runner["Service"], runner["Request"])
        )

        if not self._should_run_command_on_region(runner, region):
            return
        handler = self.session.client(
            runner["Service"], region_name=region["RegionName"],
            config=Config(retries={'max_attempts': self.settings.max_attempts, 'mode': 'standard'},
                          max_pool_connections=self.settings.max_pool_connections)
        )

        filepath = os.path.join(account_dir, region["RegionName"], f'{runner["Service"]}-{runner["Request"]}')

        method_to_call = snakecase(runner["Request"])
        parameter_keys = set()
        param_groups = self._get_parameter_group(runner, account_dir, region, parameter_keys)

        if runner.get("Parameters"):
            make_directory(filepath)
            for param_group in param_groups:
                if set(param_group.keys()) != parameter_keys:
                    continue
                file_name = urllib.parse.quote_plus('_'.join([f'{k}-{v}' for k, v in param_group.items()]))
                output_file = f"{filepath}/{file_name}.json"
                tasks.append(executor.submit(AwsScanner._get_and_save_data,
                                             output_file,
                                             handler,
                                             method_to_call,
                                             param_group,
                                             runner.get("Check", None),
                                             summary,
                                             ))
        else:
            filepath = filepath + ".json"
            tasks.append(executor.submit(AwsScanner._get_and_save_data,
                                         filepath,
                                         handler,
                                         method_to_call,
                                         {},
                                         runner.get("Check", None),
                                         summary,
                                         ))
        concurrent.futures.wait(tasks, timeout=self.settings.command_timeout, return_when=ALL_COMPLETED)
        timeout_tasks = [task for task in tasks if task.running()]
        if timeout_tasks:
            logging.exception('timeout command {}'.format(runner))
        for timeout_task in timeout_tasks:
            timeout_task.cancel()

    def _scan_region_data(self, region, account_dir, summary):
        scan_commands = load_yaml(self.settings.commands_path)
        dependable_commands = [command for command in scan_commands if command.get("Parameters", False)]
        non_dependable_commands = [command for command in scan_commands if not command.get("Parameters", False)]

        executor: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=20)
        for command in non_dependable_commands:
            executor.submit(self._run_scan_commands, region, command, account_dir, summary)
        executor.shutdown(True)

        for command in dependable_commands:
            self._run_scan_commands(region, command, account_dir, summary)

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

    def _should_run_command_on_region(self, runner: dict, region_dict: dict) -> bool:
        if runner["Service"] in self.universal_services:
            if region_dict["RegionName"] != self.settings.default_region:
                return False
        elif runner["Service"] != 'eks' and region_dict["RegionName"] not in self.session.get_available_regions(runner["Service"]):
            logger.info("Skipping region {}, as {} does not exist there"
                        .format(region_dict["RegionName"], runner["Service"]))
            return False
        return True

    def _get_parameter_group(self, runner, account_dir, region, parameter_keys: set):
        param_groups = []
        for parameter in runner.get("Parameters", []):
            name = parameter["Name"]
            value = parameter["Value"]
            is_dynamic = "|" in value
            parameter_keys.add(name)
            if not is_dynamic:
                param_groups = self._fill_simple_params(param_groups, name, value)
            else:
                group = parameter.get("Group", False)
                param_groups = self._fill_dynamic_params(param_groups, name, value, group, account_dir, region)
        return param_groups
