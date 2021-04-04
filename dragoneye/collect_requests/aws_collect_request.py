import os
from typing import List

from dragoneye.collect_requests.collect_request import CollectRequest, CloudProvider


class AwsCollectRequest(CollectRequest):
    def __init__(self,
                 account_name: str,
                 regions_filter: List[str],
                 max_attempts: int,
                 duration_session_time: int,
                 max_pool_connections: int,
                 command_timeout: int,
                 output_path: str,
                 clean: bool,
                 commands_path: str):
        super().__init__(CloudProvider.Aws, account_name, clean, output_path, commands_path)
        self.regions_filter: str = ','.join(regions_filter) if regions_filter else ''
        self.max_attempts: int = max_attempts
        self.duration_session_time: int = duration_session_time
        self.max_pool_connections: int = max_pool_connections
        self.command_timeout: int = command_timeout


class AwsAssumeRoleCollectRequest(AwsCollectRequest):
    def __init__(self,
                 account_id: str,
                 account_name: str,
                 external_id: str,
                 role_name: str,
                 commands_path: str,
                 output_path: str = os.getcwd(),
                 clean: bool = True,
                 regions_filter: List[str] = None,
                 duration_session_time: int = 3600,
                 max_attempts: int = 10,
                 max_pool_connections: int = 50,
                 command_timeout: int = 600):
        super().__init__(account_name, regions_filter, max_attempts,
                         duration_session_time, max_pool_connections, command_timeout, output_path, clean, commands_path)
        self.external_id: str = external_id
        self.role_name: str = role_name
        self.account_id: str = account_id


class AwsAccessKeyCollectRequest(AwsCollectRequest):
    def __init__(self,
                 account_name: str,
                 commands_path: str,
                 profile_name: str = None,
                 max_attempts: int = 10,
                 output_path: str = os.getcwd(),
                 clean: bool = True,
                 regions_filter: List[str] = None,
                 duration_session_time: int = 600,
                 max_pool_connections: int = 50,
                 command_timeout: int = 600):
        super().__init__(account_name, regions_filter, max_attempts,
                         duration_session_time, max_pool_connections, command_timeout, output_path, clean, commands_path)
        self.profile_name: str = profile_name
