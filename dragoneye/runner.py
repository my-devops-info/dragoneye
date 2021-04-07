from dragoneye.cloud_scanner.aws.aws_scan_request import AwsCloudScanSettings, AwsCredentials
from dragoneye.cloud_scanner.aws.aws_scanner import AwsScanner
from dragoneye.cloud_scanner.aws.aws_session_factory import AwsSessionFactory
from dragoneye.cloud_scanner.aws.aws_utils import AwsUtils
from dragoneye.cloud_scanner.azure.azure_authorizer import AzureAuthorizer
from dragoneye.cloud_scanner.azure.azure_scan_request import AzureCloudScanSettings, AzureCredentials
from dragoneye.cloud_scanner.azure.azure_scanner import AzureScanner
from dragoneye.cloud_scanner.base_cloud_scanner import CloudCredentials, CloudScanSettings, CloudProvider
from dragoneye.dragoneye_exception import DragoneyeException


def scan(credentials: CloudCredentials, collect_settings: CloudScanSettings) -> str:
    if collect_settings.cloud_provider == CloudProvider.AWS:
        aws_collect_settings: AwsCloudScanSettings = collect_settings
        aws_credentials: AwsCredentials = credentials
        session = AwsSessionFactory.get_session(aws_credentials, AwsUtils.get_default_region())
        cloud_scanner = AwsScanner(session, aws_collect_settings)
        output_path = cloud_scanner.scan()
    elif collect_settings.cloud_provider == CloudProvider.AZURE:
        azure_collect_settings: AzureCloudScanSettings = collect_settings
        azure_credentials: AzureCredentials = credentials
        auth_header = AzureAuthorizer.get_authorization_token(azure_credentials)
        cloud_scanner = AzureScanner(auth_header, azure_collect_settings)
        output_path = cloud_scanner.scan()
    else:
        raise DragoneyeException(f'Unknown cloud provider. '
                                 f'Got: {collect_settings.cloud_provider}, '
                                 f'expected: {CloudProvider.AWS} or {CloudProvider.AZURE}')
    return output_path


def test_connectivity(cloud_credentials: CloudCredentials) -> bool:
    try:
        if isinstance(cloud_credentials, AwsCredentials):
            AwsSessionFactory.get_session(cloud_credentials)
        elif isinstance(cloud_credentials, AzureCredentials):
            AzureAuthorizer.get_authorization_token(cloud_credentials)
        else:
            return False
        return True
    except Exception:
        # TODO: log
        return False
