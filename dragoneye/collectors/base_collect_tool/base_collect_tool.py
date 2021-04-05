from abc import abstractmethod

from dragoneye.collect_requests.collect_request import CollectRequest


class BaseCollect:
    @classmethod
    @abstractmethod
    def collect(cls, collect_request: CollectRequest) -> str:
        pass

    @classmethod
    @abstractmethod
    def test_authentication(cls, collect_request: CollectRequest) -> bool:
        pass
