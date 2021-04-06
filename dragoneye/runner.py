from dragoneye.cloud_scanner.aws.aws_scan_request import AwsCloudScanSettings, AwsCredentials
from dragoneye.cloud_scanner.aws.aws_scanner import AwsScanner
from dragoneye.cloud_scanner.aws.aws_session_factory import AwsSessionFactory
from dragoneye.cloud_scanner.azure.azure_authorizer import AzureAuthorizer
from dragoneye.cloud_scanner.azure.azure_scan_request import AzureCloudScanSettings, AzureCredentials
from dragoneye.cloud_scanner.azure.azure_scanner import AzureScanner
from dragoneye.cloud_scanner.base_cloud_scanner import CloudCredentials, CloudScanSettings, CloudProvider
from dragoneye.dragoneye_exception import DragoneyeException


def run(credentials: CloudCredentials, collect_settings: CloudScanSettings) -> str:

    if collect_settings.cloud_provider == CloudProvider.Aws:
        aws_collect_settings: AwsCloudScanSettings = collect_settings
        aws_credentials: AwsCredentials = credentials
        session = AwsSessionFactory.get_session(aws_credentials)
        output_path = AwsScanner.collect(session, aws_collect_settings)
    elif collect_settings.cloud_provider == CloudProvider.Azure:
        azure_collect_settings: AzureCloudScanSettings = collect_settings
        azure_credentials: AzureCredentials = credentials
        auth_header = AzureAuthorizer.get_authorization_token(azure_credentials)
        output_path = AzureScanner.collect(auth_header, azure_collect_settings)
    else:
        raise DragoneyeException(f'Unknown cloud provider. '
                                 f'Got: collect_settings.cloud_provider, '
                                 f'expected: {CloudProvider.Aws} or {CloudProvider.Azure}')
    return output_path