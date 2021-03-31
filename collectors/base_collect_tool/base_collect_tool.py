from abc import abstractmethod

from collect_requests.collect_request import CollectRequest


class BaseCollect:
    @classmethod
    @abstractmethod
    def collect(cls, collect_request: CollectRequest) -> str:
        pass

    @classmethod
    @abstractmethod
    def test_authentication(cls, collect_request: CollectRequest) -> bool:
        pass

    @staticmethod
    @abstractmethod
    def add_parser_args(parser) -> None:
        pass

    @staticmethod
    @abstractmethod
    def convert_args_to_request(args) -> CollectRequest:
        pass
