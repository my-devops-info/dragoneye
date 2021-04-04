import os
from typing import List

from dragoneye.collect_requests.collect_request import CollectRequest, CloudProvider, CloudCredentials, CollectSettings

class AwsCollectRequest(CollectRequest):
    def __init__(self,
                 commands_path: str,
                 account_name: str = 'default',
                 regions_filter: List[str] = None,
                 max_attempts: int = 10,
                 duration_session_time: int = 3600,
                 max_pool_connections: int = 50,
                 command_timeout: int = 600,
                 output_path: str = os.getcwd(),
                 clean: bool = True):
        super().__init__(CloudProvider.Aws, account_name, clean, output_path, commands_path)
        self.regions_filter: str = ','.join(regions_filter) if regions_filter else ''
        self.max_attempts: int = max_attempts
        self.duration_session_time: int = duration_session_time
        self.max_pool_connections: int = max_pool_connections
        self.command_timeout: int = command_timeout

    @staticmethod
    def from_args(args):
        return AwsCollectSettings(account_name=args.account_name,
                                  clean=args.clean,
                                  regions_filter=args.regions_filter,
                                  duration_session_time=args.duration_session_time,
                                  max_attempts=args.max_attempts,
                                  max_pool_connections=args.max_pool_connections,
                                  command_timeout=args.command_timeout,
                                  output_path=args.output_path,
                                  commands_path=args.commands_path)


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
