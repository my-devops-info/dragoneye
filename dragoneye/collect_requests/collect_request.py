from enum import Enum

from dataclasses import dataclass


class CloudProvider(str, Enum):
    Aws = 'aws'
    Azure = 'azure'


@dataclass
class CollectRequest:
    cloud_provider: CloudProvider
    account_name: str
    clean: bool
    output_path: str
