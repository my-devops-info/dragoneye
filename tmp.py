from collect_requests.aws_collect_request import AwsDirectCollectRequest
from collect_requests.azure_collect_request import AzureCollectRequest
from main import collect

request1 = AwsDirectCollectRequest(account_name='dev',
                                   account_id='553432699559',
                                   regions_filter=['us-east-1'])
request2 = AzureCollectRequest(
    account_name='test',
    tenant_id='b794a32d-6125-4f2a-b1c1-ad35b8201f93',
    subscription_id='136bb9a7-1aa2-4350-ad9d-c2b8ead61e72',
    client_id='1fad6728-319e-4552-a93a-5fb66a1471c1',
    client_secret='Q5CLaBwHhXyzYSgLN~zU055oq2IkJulsp.',
    clean=True
)

print(collect(request1))
