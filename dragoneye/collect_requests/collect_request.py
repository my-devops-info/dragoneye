from enum import Enum

from dataclasses import dataclass


class CloudProvider(str, Enum):
    Aws = 'aws'
    Azure = 'azure'


class CloudCredentials:
    @staticmethod
    @abstractmethod
    def from_args(args):
        pass


class CollectSettings:
    def __init__(self, cloud_provider: CloudProvider, account_name: str, clean: bool, output_path: str, commands_path: str):
        self.cloud_provider: CloudProvider = cloud_provider
        self.account_name: str = account_name
        self.clean: bool = clean
        self.output_path: str = output_path
        self.commands_path: str = commands_path

    @staticmethod
    @abstractmethod
    def from_args(args):
        pass


class CollectRequest:
    cloud_provider: CloudProvider
    account_name: str
    clean: bool
    output_path: str
    commands_path: str
