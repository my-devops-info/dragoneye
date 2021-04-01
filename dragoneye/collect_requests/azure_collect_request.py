import os

from dragoneye.collect_requests.collect_request import CollectRequest, CloudProvider


class AzureCollectRequest(CollectRequest):
    def __init__(self,
                 tenant_id: str,
                 account_name: str,
                 subscription_id: str,
                 client_id: str,
                 client_secret: str,
                 commands_path: str,
                 output_path: str = os.getcwd(),
                 clean: bool = True
                 ):
        super().__init__(CloudProvider.Azure, account_name, clean, output_path, commands_path)
        self.tenant_id: str = tenant_id
        self.subscription_id: str = subscription_id
        self.client_id: str = client_id
        self.client_secret: str = client_secret
