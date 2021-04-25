import os
from enum import Enum
from typing import List

from dragoneye.cloud_scanner.base_cloud_scanner import CloudScanSettings, CloudProvider


class AwsRegionType(str, Enum):
    STANDARD = 'Standard'
    GOV = 'Gov'
    CHINA = 'China'


class AwsCloudScanSettings(CloudScanSettings):
    def __init__(self,
                 commands_path: str,
                 account_name: str,
                 regions_filter: List[str] = None,
                 max_attempts: int = 10,
                 duration_session_time: int = 3600,
                 max_pool_connections: int = 50,
                 command_timeout: int = 600,
                 output_path: str = os.getcwd(),
                 should_clean_before_scan: bool = True,
                 region_type: AwsRegionType = AwsRegionType.STANDARD):
        super().__init__(CloudProvider.AWS, account_name, should_clean_before_scan, output_path, commands_path)
        self.regions_filter: str = ','.join(regions_filter) if regions_filter else ''
        self.max_attempts: int = max_attempts
        self.duration_session_time: int = duration_session_time
        self.max_pool_connections: int = max_pool_connections
        self.command_timeout: int = command_timeout
        self.region_type: AwsRegionType = region_type
