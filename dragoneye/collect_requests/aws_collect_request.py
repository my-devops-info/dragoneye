import os
from abc import abstractmethod
from typing import List, Optional

from dragoneye.collect_requests.collect_request import CollectRequest, CloudProvider, CloudCredentials, CollectSettings


class AwsAssumeRoleCredentials(CloudCredentials):
    def __init__(self,
                 account_id: str,
                 external_id: str,
                 role_name: str):
        self.external_id: str = external_id
        self.role_name: str = role_name
        self.account_id: str = account_id

    @staticmethod
    def from_args(args):
        return AwsAssumeRoleCredentials(args.account_id, args.external_id, args.role_name)


class AwsAccessKeyCredentials(CloudCredentials):
    def __init__(self, profile_name: Optional[str] = None):
        self.profile_name: Optional[str] = profile_name

    @staticmethod
    def from_args(args):
        return AwsAccessKeyCredentials(args.profile_name)


class AwsCollectSettings(CollectSettings):
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


class AwsCollectRequest(CollectRequest):
    def __init__(self, credentials: CloudCredentials, collect_settings: AwsCollectSettings):
        super().__init__(credentials, collect_settings)
        self.collect_settings: AwsCollectSettings = collect_settings

    @staticmethod
    @abstractmethod
    def from_args(args):
        if args.assume_role:
            credentials = AwsAssumeRoleCredentials.from_args(args)
        else:
            credentials = AwsAccessKeyCredentials.from_args(args)
        settings = AwsCollectSettings.from_args(args)

        return AwsCollectRequest(credentials, settings)
