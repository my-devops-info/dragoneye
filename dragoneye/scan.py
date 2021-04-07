import os
import click
from click_aliases import ClickAliasedGroup

from dragoneye import run
from dragoneye.cloud_scanner.aws.aws_scan_request import AwsCredentials, AwsCloudScanSettings
from dragoneye.cloud_scanner.aws.aws_utils import AwsUtils
from dragoneye.cloud_scanner.azure.azure_scan_request import AzureCredentials, AzureCloudScanSettings


@click.group(name='scan',
             short_help='Scan cloud account.',
             help='Scan cloud account. Currently supported: AWS, Azure',
             cls=ClickAliasedGroup)
def scan():
    pass


@scan.command(name='azure',
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

    run(azure_credentials, azure_collect_settings)


@scan.command(name='aws',
              short_help='Scan an AWS cloud account',
              help='Scan an AWS cloud account.')
@click.option('--cloud-account-name', '-n',
              help='The name of your cloud account',
              type=click.STRING)
# For assume role
@click.option('--role-name',
              help='IAM role name to assume',
              type=click.STRING)
@click.option('--external-id',
              help='External id',
              type=click.STRING)
@click.option('--account-id',
              help='ID of AWS account to be added',
              type=click.STRING)
# Using keys
@click.option('--aws-access-key-id',
              help='aws access key id',
              type=click.STRING)
@click.option('--aws-secret-access-key',
              help='aws secret access key',
              type=click.STRING)
# user aws profile
@click.option('--profile',
              help='aws profile',
              type=click.STRING)
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
    run(aws_credentials, aws_collect_settings)


if __name__ == '__main__':
    scan()
