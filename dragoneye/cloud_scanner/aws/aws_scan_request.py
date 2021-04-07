import os
from typing import List

from dragoneye.cloud_scanner.base_cloud_scanner import CloudCredentials, CloudScanSettings, CloudProvider


class AwsCredentials(CloudCredentials):
    def __init__(self,
                 account_id: str,
                 external_id: str,
                 role_name: str,
                 aws_access_key_id: str,
                 aws_secret_access_key: str,
                 profile_name: str,
                 session_duration: int = 3600):
        self.external_id: str = external_id
        self.role_name: str = role_name
        self.account_id: str = account_id
        self.aws_access_key_id: str = aws_access_key_id
        self.aws_secret_access_key: str = aws_secret_access_key
        self.profile_name: str = profile_name
        self.session_duration: int = session_duration


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
                 should_clean_before_collect: bool = True):
        super().__init__(CloudProvider.Aws, account_name, should_clean_before_collect, output_path, commands_path)
        self.regions_filter: str = ','.join(regions_filter) if regions_filter else ''
        self.default_region = default_region
        self.max_attempts: int = max_attempts
        self.duration_session_time: int = duration_session_time
        self.max_pool_connections: int = max_pool_connections
        self.command_timeout: int = command_timeout
