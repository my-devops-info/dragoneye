import os
from concurrent.futures.thread import ThreadPoolExecutor
from typing import List

import requests
import json

from requests import Response

from dragoneye.collect_requests.azure_collect_request import AzureCollectRequest
from dragoneye.collectors.base_collect_tool.base_collect_tool import BaseCollect
from dragoneye.utils.misc_utils import elapsed_time, invoke_get_request, init_directory, get_commands, get_dynamic_values_from_files, \
    custom_serializer


class AzureCollectTool(BaseCollect):
    @classmethod
    @elapsed_time
    def collect(cls, collect_request: AzureCollectRequest) -> str:
        account_name = collect_request.account_name
        tenant_id = collect_request.tenant_id
        subscription_id = collect_request.subscription_id
        client_id = collect_request.client_id
        client_secret = collect_request.client_secret

        headers = {
            'Authorization': cls._get_authorization_token(tenant_id, client_id, client_secret)
        }

        base_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../..')
        account_data_dir = init_directory(base_path, account_name, collect_request.clean)
        collect_commands = get_commands()
        resource_groups = cls._get_resource_groups(headers, subscription_id, account_data_dir)

        dependable_commands = [command for command in collect_commands if command.get("Parameters", False)]
        non_dependable_commands = [command for command in collect_commands if not command.get("Parameters", False)]

        executor: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=20)
        for non_dependable_command in non_dependable_commands:
            executor.submit(cls._execute_collect_commands, non_dependable_command, subscription_id, headers, account_data_dir, resource_groups)
        executor.shutdown(True)

        for dependable_command in dependable_commands:
            cls._execute_collect_commands(dependable_command, subscription_id, headers, account_data_dir, resource_groups)

        return os.path.abspath(os.path.join(account_data_dir, '..'))

    @classmethod
    def test_authentication(cls, collect_request: AzureCollectRequest) -> bool:
        try:
            cls._get_authorization_token(collect_request.tenant_id, collect_request.client_id, collect_request.client_secret)
            return True
        except Exception:
            return False

    @classmethod
    def _execute_collect_commands(cls, collect_command: dict, subscription_id: str, headers: dict,
                                  account_data_dir: str, resource_groups: List[str]) -> None:
        request = collect_command['Request']
        name = collect_command['Name']
        parameters = collect_command.get('Parameters', [])
        url = request.replace('{subscriptionId}', subscription_id)

        results = cls._get_results(url, headers, parameters, account_data_dir, resource_groups)
        cls._save_result(account_data_dir, results, name)

    @staticmethod
    def _get_authorization_token(tenant_id: str, client_id: str, client_secret: str) -> str:
        response = requests.post(
            url=f'https://login.microsoftonline.com/{tenant_id}/oauth2/token',
            data={
                'grant_type': 'client_credentials',
                'client_id': client_id,
                'client_secret': client_secret,
                'resource': 'https://management.azure.com/'
            }
        )

        if response.status_code != 200:
            raise Exception(f'Failed to authenticate. status code: {response.status_code}\nReason: {response.text}')

        response_body = json.loads(response.text)
        access_token = response_body['access_token']
        return f'Bearer {access_token}'

    @classmethod
    def _save_result(cls, account_data_dir: str, result: dict, filename: str) -> None:
        cls._add_resource_group(result)
        filepath = os.path.join(account_data_dir, filename + '.json')
        with open(filepath, "w+") as file:
            json.dump(result, file, indent=4, default=custom_serializer)

    @classmethod
    def _get_results(cls, url: str, headers: dict, parameters: List[dict], account_data_dir: str, resource_groups: List[str]) -> dict:
        results = {'value': []}
        if parameters:
            for parameter in parameters:
                param_names = parameter['Name']
                param_dynamic_value = parameter['Value']
                param_real_values = get_dynamic_values_from_files(param_dynamic_value, account_data_dir)

                for param_real_value in param_real_values:
                    modified_url = url
                    zipped = zip(param_names.split(' '), param_real_value.split(' '))
                    for param, value in zipped:
                        modified_url = modified_url.replace('{{{0}}}'.format(param), value)

                    cls._get_results_for_resource_groups(results, modified_url, headers, resource_groups)
        else:
            cls._get_results_for_resource_groups(results, url, headers, resource_groups)

        return results

    @classmethod
    def _get_results_for_resource_groups(cls, results: dict, modified_url: str, headers: dict, resource_groups: List[str]) -> None:
        if '/{resourceGroupName}/' in modified_url:
            for resource_group in resource_groups:
                response = invoke_get_request(modified_url.replace('{{{0}}}'.format('resourceGroupName'), resource_group), headers)
                cls._concat_results(results, response)
        else:
            response = invoke_get_request(modified_url, headers)
            cls._concat_results(results, response)

    @staticmethod
    def _concat_results(results: dict, response: Response) -> None:
        if response.status_code == 200:
            result = json.loads(response.text)
            if 'value' in result:
                results['value'].extend(result['value'])
            else:
                results['value'].append(result)

    @classmethod
    def _get_resource_groups(cls, headers: dict, subscription_id: str, account_data_dir: str) -> List[str]:
        results = cls._get_results(f'https://management.azure.com/subscriptions/{subscription_id}/resourcegroups?api-version=2020-09-01',
                                   headers, [], account_data_dir, [])
        cls._save_result(account_data_dir, results, 'resource-groups')
        return get_dynamic_values_from_files('resource-groups.json|.value[].name', account_data_dir)

    @staticmethod
    def _add_resource_group(results: dict) -> None:
        for item in results['value']:
            item_id = item['id']
            resource_group = item_id.split('resourceGroups/')[1].split('/')[0]
            item['resourceGroup'] = resource_group

    @classmethod
    def add_parser_args(cls, parser):
        parser.add_argument(
            "--account",
            help="Account to collect from",
            required=False,
            type=str,
            dest="account_name",
        )
        parser.add_argument(
            "--clean",
            help="Remove any existing data for the account before gathering",
            action="store_true",
        )
        parser.add_argument(
            "--tenant-id",
            help="The tenant id to collect data from",
            required=True,
            type=str,
            dest="tenant_id"
        )
        parser.add_argument(
            "--subscription-id",
            help="The subscription id to collect data from",
            required=True,
            type=str,
            dest="subscription_id"
        )
        parser.add_argument(
            "--client-id",
            help="The client id to collect data from",
            required=True,
            type=str,
            dest="client_id"
        )
        parser.add_argument(
            "--client-secret",
            help="The tenant id to collect data from",
            required=True,
            type=str,
            dest="client_secret"
        )

    @staticmethod
    def convert_args_to_request(args):
        pass
