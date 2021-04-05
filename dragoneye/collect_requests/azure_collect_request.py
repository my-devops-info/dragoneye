import os

from dragoneye.collect_requests.collect_request import CollectRequest, CloudProvider, CloudCredentials, CollectSettings


class AzureCredentials(CloudCredentials):
    def __init__(self,
                 tenant_id: str,
                 subscription_id: str,
                 client_id: str,
                 client_secret: str
                 ):
        self.tenant_id: str = tenant_id
        self.subscription_id: str = subscription_id
        self.client_id: str = client_id
        self.client_secret: str = client_secret

    @staticmethod
    def from_args(args):
        return AzureCredentials(tenant_id=args.tenant_id,
                                subscription_id=args.subscription_id,
                                client_id=args.client_id,
                                client_secret=args.client_secret)


class AzureCollectSettings(CollectSettings):
    def __init__(self,
                 commands_path: str,
                 account_name: str = 'default',
                 output_path: str = os.getcwd(),
                 clean: bool = True
                 ):
        super().__init__(cloud_provider=CloudProvider.Azure,
                         account_name=account_name,
                         clean=clean,
                         output_path=output_path,
                         commands_path=commands_path)

    @staticmethod
    def from_args(args):
        return AzureCollectSettings(account_name=args.account_name,
                                    clean=args.clean,
                                    output_path=args.output_path,
                                    commands_path=args.commands_path)


class AzureCollectRequest(CollectRequest):
    @staticmethod
    def from_args(args):
        credentials = AzureCredentials.from_args(args)
        settings = AzureCollectSettings.from_args(args)
        return AzureCollectRequest(credentials, settings)
