import os

from dragoneye.collect_requests.collect_request import CollectRequest, CloudProvider, CloudCredentials, CollectSettings


class AzureCollectRequest(CollectRequest):
    @staticmethod
    def from_args(args):
        credentials = AzureCredentials.from_args(args)
        settings = AzureCollectSettings.from_args(args)
        return AzureCollectRequest(credentials, settings)
