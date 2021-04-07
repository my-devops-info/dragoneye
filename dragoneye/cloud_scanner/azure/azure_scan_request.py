import os

from dragoneye.cloud_scanner.base_cloud_scanner import CloudCredentials, CloudScanSettings, CloudProvider


class AzureCredentials(CloudCredentials):
    def __init__(self,
                 tenant_id: str,
                 client_id: str,
                 client_secret: str
                 ):
        self.tenant_id: str = tenant_id
        self.client_id: str = client_id
        self.client_secret: str = client_secret


class AzureCloudScanSettings(CloudScanSettings):
    def __init__(self,
                 commands_path: str,
                 subscription_id: str,
                 account_name: str,
                 output_path: str = os.getcwd(),
                 should_clean_before_collect: bool = True
                 ):
        super().__init__(cloud_provider=CloudProvider.Azure,
                         account_name=account_name,
                         should_clean_before_collect=should_clean_before_collect,
                         output_path=output_path,
                         commands_path=commands_path)
        self.subscription_id = subscription_id
