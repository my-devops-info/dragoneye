import os

import click
from click_aliases import ClickAliasedGroup

from dragoneye.version import __version__
from dragoneye.cloud_scanner.aws.aws_scanner import AwsScanner
from dragoneye.cloud_scanner.aws.aws_session_factory import AwsSessionFactory
from dragoneye.cloud_scanner.azure.azure_scanner import AzureScanner
from dragoneye.cloud_scanner.azure.azure_authorizer import AzureAuthorizer
from dragoneye.cloud_scanner.aws.aws_scan_settings import AwsCloudScanSettings
from dragoneye.cloud_scanner.azure.azure_scan_settings import AzureCloudScanSettings
from dragoneye.utils.value_validator import validate_uuid, validate_path


@click.group(name='scan',
             help='Execute data-fetching API commands on a cloud account at a large scale quickly. Currently supported: AWS, Azure',
             cls=ClickAliasedGroup)
@click.version_option(__version__)
def scan_cli():
    pass


def safe_cli_entry_point():
    try:
        scan_cli()
    except Exception as ex:
        click.echo(ex)


@scan_cli.command(name='azure',
                  short_help='Scan an Azure cloud account',
                  help='Scan an Azure cloud account. '
                       '\n\nSCAN_COMMANDS_PATH: The file path to the yaml file that contains all the scan commands to run')
@click.argument('scan-commands-path',
                type=click.STRING)
@click.option('--cloud-account-name', '-n',
              help='The name of your cloud account, the default value is \'default\'',
              type=click.STRING,
              default='default')
@click.option('--subscription-id', '-i',
              help='ID of Azure subscription to be added',
              type=click.STRING,
              required=True)
@click.option('--tenant-id', '-t',
              help='ID of Azure tenant of this subscription',
              type=click.STRING,
              required=True)
@click.option('--client-id', '-c',
              help='The client id created in Azure to connect to cloudrail',
              type=click.STRING,
              required=True)
@click.option('--client-secret', '-s',
              help='The client secret created in Azure connect to cloudrail',
              type=click.STRING,
              required=True)
@click.option("--clean",
              help="Remove any existing data for the account before gathering",
              is_flag=True,
              default=True)
@click.option('--output-path',
              help='The path in which the scan results will be saved on. Defaults to current working directory.',
              type=click.STRING,
              default=os.getcwd())
def azure(cloud_account_name: str,
          subscription_id: str, client_id: str, client_secret: str, tenant_id: str,
          scan_commands_path, clean, output_path):
    validate_uuid(subscription_id, 'Invalid subscription id')
    validate_uuid(tenant_id, 'Invalid tenant id')
    validate_uuid(client_id, 'Invalid client id')
    validate_path(scan_commands_path)

    azure_scan_settings = AzureCloudScanSettings(
        commands_path=scan_commands_path,
        account_name=cloud_account_name,
        subscription_id=subscription_id,
        should_clean_before_scan=clean,
        output_path=output_path)

    auth_header = AzureAuthorizer.get_authorization_token(tenant_id, client_id, client_secret)
    output_path = AzureScanner(auth_header, azure_scan_settings).scan()
    click.echo(f'Results saved to {output_path}')


@scan_cli.command(name='aws',
                  short_help='Scan an AWS cloud account',
                  help='Scan an AWS cloud account. \n\nSCAN_COMMANDS_PATH: The file path to the yaml file that contains all the scan commands to run')
@click.argument('scan-commands-path',
                type=click.STRING)
@click.option('--cloud-account-name', '-n',
              help='The name of your cloud account, the default value is \'default\'',
              type=click.STRING,
              default='default')
@click.option('--profile',
              help='aws profile',
              type=click.STRING)
@click.option("--regions",
              help="Filter and query AWS only for the given regions (comma separated)",
              type=click.STRING,
              default='')
@click.option("--clean",
              help="Remove any existing data for the account before gathering",
              is_flag=True,
              default=True)
@click.option('--output-path',
              help='The path in which the scan results will be saved on. Defaults to current working directory.',
              type=click.STRING,
              default=os.getcwd())
@click.option('--default-region',
              help='The default region for scanning universal services. Defaults to the value of the AWS_DEFAULT_REGION environment variable.',
              type=click.STRING)
def aws(cloud_account_name,
        profile,
        regions,
        scan_commands_path,
        clean,
        output_path,
        default_region):
    aws_scan_settings = AwsCloudScanSettings(
        commands_path=scan_commands_path,
        account_name=cloud_account_name,
        regions_filter=regions.split(','),
        should_clean_before_scan=clean,
        output_path=output_path,
        default_region=default_region)

    validate_path(scan_commands_path)
    session = AwsSessionFactory.get_session(profile, default_region)
    output_path = AwsScanner(session, aws_scan_settings).scan()
    click.echo(f'Results saved to {output_path}')


if __name__ == '__main__':
    safe_cli_entry_point()
