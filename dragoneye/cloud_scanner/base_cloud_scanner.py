from abc import abstractmethod
from enum import Enum


class CloudProvider(str, Enum):
    Aws = 'aws'
    Azure = 'azure'


class CloudCredentials:
    pass


class CloudScanSettings:
    def __init__(self,
                 cloud_provider: CloudProvider,
                 account_name: str,
                 should_clean_before_collect: bool,
                 output_path: str,
                 commands_path: str):
        self.cloud_provider: CloudProvider = cloud_provider
        self.account_name: str = account_name
        self.clean: bool = should_clean_before_collect
        self.output_path: str = output_path
        self.commands_path: str = commands_path


class BaseCloudScanner:
    @abstractmethod
    def scan(self) -> str:
        pass

    @abstractmethod
    def test_connectivity(self, cloud_credentials: CloudCredentials):
        pass
