import os

from dragoneye.cloud_scanner.base_cloud_scanner import CloudScanSettings, CloudProvider


class AzureCloudScanSettings(CloudScanSettings):
    def __init__(self,
                 commands_path: str,
                 subscription_id: str,
                 account_name: str,
                 output_path: str = os.getcwd(),
                 should_clean_before_scan: bool = True
                 ):
        super().__init__(cloud_provider=CloudProvider.AZURE,
                         account_name=account_name,
                         should_clean_before_scan=should_clean_before_scan,
                         output_path=output_path,
                         commands_path=commands_path)
        self.subscription_id = subscription_id
