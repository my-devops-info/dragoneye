import os
from typing import List

import click
from click_aliases import ClickAliasedGroup

from dragoneye.runner import scan
from dragoneye.cloud_scanner.aws.aws_scan_request import AwsCredentials, AwsCloudScanSettings
from dragoneye.cloud_scanner.aws.aws_utils import AwsUtils
from dragoneye.cloud_scanner.azure.azure_scan_request import AzureCredentials, AzureCloudScanSettings


class MutexOption(click.Option):
    def __init__(self, *args, **kwargs):
        self.not_required_if: list = kwargs.pop("not_required_if")

        assert self.not_required_if, "'not_required_if' parameter required"
        kwargs["help"] = (kwargs.get("help", "") + ".\tOption is mutually exclusive with " + ", ".join(self.not_required_if) + ".").strip()
        super().__init__(*args, **kwargs)

    def handle_parse_result(self, ctx, opts, args):
        current_opt: bool = self.consume_value(ctx, opts)
        for other_param in ctx.command.get_params(ctx):
            if other_param is self:
                continue
            if other_param.human_readable_name in self.not_required_if:
                other_opt: bool = other_param.consume_value(ctx, opts)
                if other_opt:
                    if current_opt:
                        raise click.UsageError(
                            "Illegal usage: '" + str(self.name)
                            + "' is mutually exclusive with "
                            + str(other_param.human_readable_name) + "."
                        )

                    self.required = None
        return super().handle_parse_result(ctx, opts, args)


aws_mutex_groups = {
    'assume-role': ['role-name', 'external-id', 'account-id'],
    'access-key': ['aws-access-key-id', 'aws-secret-access-key'],
    'profile': ['profile']
}


def get_aws_mutex_groups(my_group: str) -> List[str]:
    result = []
    for group, group_params in aws_mutex_groups.items():
        if group != my_group:
            result.extend(group_params)
    return result


@click.group(name='scan',
             short_help='Scan cloud account.',
             help='Scan cloud account. Currently supported: AWS, Azure',
             cls=ClickAliasedGroup)
def scan_cli():
    pass


@scan_cli.command(name='azure',
                  short_help='Scan an Azure cloud account',
                  help='Scan an Azure cloud account.')
@click.option('--cloud-account-name', '-n',
              help='The name of your cloud account',
              type=click.STRING)
@click.option('--subscription-id', '-i',
              help='ID of Azure subscription to be added',
              type=click.STRING)
@click.option('--tenant-id', '-t',
              help='ID of Azure tenant of this subscription',
              type=click.STRING)
@click.option('--client-id', '-c',
              help='The client id created in Azure to connect to cloudrail',
              type=click.STRING)
@click.option('--client-secret', '-s',
              help='The client secret created in Azure connect to cloudrail',
              type=click.STRING)
@click.option('--scan-commands-path',
              help='The file path to the yaml file that contains all the scan commands to run',
              type=click.STRING,
              required=True)
@click.option("--clean",
              help="Remove any existing data for the account before gathering",
              is_flag=True,
              default=True)
@click.option('--output-path',
              help='The path in which the collect results will be saved on. Defaults to current working directory.',
              type=click.STRING,
              default=os.getcwd())
def add_cloud_account_azure(cloud_account_name: str,
                            subscription_id: str, client_id: str, client_secret: str, tenant_id: str,
                            scan_commands_path, clean, output_path):
    azure_credentials = AzureCredentials(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret)

    azure_collect_settings = AzureCloudScanSettings(
        commands_path=scan_commands_path,
        account_name=cloud_account_name,
        subscription_id=subscription_id,
        should_clean_before_collect=clean,
        output_path=output_path)

    scan(azure_credentials, azure_collect_settings)


@scan_cli.command(name='aws',
                  short_help='Scan an AWS cloud account',
                  help='Scan an AWS cloud account.')
@click.option('--cloud-account-name', '-n',
              help='The name of your cloud account',
              type=click.STRING)
# For assume role
@click.option('--role-name',
              help='IAM role name to assume',
              type=click.STRING,
              cls=MutexOption,
              not_required_if=get_aws_mutex_groups('assume-role'))
@click.option('--external-id',
              help='External id',
              type=click.STRING,
              cls=MutexOption,
              not_required_if=get_aws_mutex_groups('assume-role'))
@click.option('--account-id',
              help='ID of AWS account to be added',
              type=click.STRING,
              cls=MutexOption,
              not_required_if=get_aws_mutex_groups('assume-role'))
# Using keys
@click.option('--aws-access-key-id',
              help='aws access key id',
              type=click.STRING,
              cls=MutexOption,
              not_required_if=get_aws_mutex_groups('access-key'))
@click.option('--aws-secret-access-key',
              help='aws secret access key',
              type=click.STRING,
              cls=MutexOption,
              not_required_if=get_aws_mutex_groups('access-key'))
# user aws profile
@click.option('--profile',
              help='aws profile',
              type=click.STRING,
              cls=MutexOption,
              not_required_if=get_aws_mutex_groups('profile'))
@click.option("--regions",
              help="Filter and query AWS only for the given regions (comma separated)",
              type=click.STRING,
              default='')
# common to all providers
@click.option('--scan-commands-path',
              help='The file path to the yaml file that contains all the scan commands to run',
              type=click.STRING,
              required=True)
@click.option("--clean",
              help="Remove any existing data for the account before gathering",
              is_flag=True,
              default=True)
@click.option('--output-path',
              help='The path in which the collect results will be saved on. Defaults to current working directory.',
              type=click.STRING,
              default=os.getcwd())
def aws(cloud_account_name,
        role_name, external_id, account_id,  # assume role
        aws_access_key_id, aws_secret_access_key,  # keys
        profile,  # aws profile
        regions,
        scan_commands_path, clean, output_path):
    aws_credentials = AwsCredentials(role_name, external_id, account_id,
                                     aws_access_key_id, aws_secret_access_key,
                                     profile)
    aws_collect_settings = AwsCloudScanSettings(
        commands_path=scan_commands_path,
        account_name=cloud_account_name,
        default_region=AwsUtils.get_default_region(),
        regions_filter=regions.split(','),
        should_clean_before_collect=clean,
        output_path=output_path
    )
    scan(aws_credentials, aws_collect_settings)


if __name__ == '__main__':
    scan_cli()
