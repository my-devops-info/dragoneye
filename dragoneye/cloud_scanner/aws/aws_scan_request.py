import os
from typing import List

from dragoneye.cloud_scanner.base_cloud_scanner import CloudScanSettings, CloudProvider


class AwsCloudScanSettings(CloudScanSettings):
    def __init__(self,
                 commands_path: str,
                 account_name: str,
                 default_region: str,
                 regions_filter: List[str] = None,
                 max_attempts: int = 10,
                 duration_session_time: int = 3600,
                 max_pool_connections: int = 50,
                 command_timeout: int = 600,
                 output_path: str = os.getcwd(),
                 should_clean_before_scan: bool = True):
        super().__init__(CloudProvider.AWS, account_name, should_clean_before_scan, output_path, commands_path)
        self.regions_filter: str = ','.join(regions_filter) if regions_filter else ''
        self.default_region = default_region
        self.max_attempts: int = max_attempts
        self.duration_session_time: int = duration_session_time
        self.max_pool_connections: int = max_pool_connections
        self.command_timeout: int = command_timeout
