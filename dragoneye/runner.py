from dragoneye.collectors.aws_collect_tool.aws_collect_tool import AwsCollectTool
from dragoneye.collectors.azure_collect_tool.azure_collect_tool import AzureCollectTool
from dragoneye import AzureCollectRequest
from dragoneye.collect_requests.aws_collect_request import AwsCollectRequest
from dragoneye.collect_requests.collect_request import CollectRequest


def collect(collect_request: CollectRequest) -> str:
    if isinstance(collect_request, AwsCollectRequest):
        output_path = AwsCollectTool.collect(collect_request)
    elif isinstance(collect_request, AzureCollectRequest):
        output_path = AzureCollectTool.collect(collect_request)
    else:
        raise Exception(f'Unknown collect request type. '
                        f'Got: {type(collect_request).__name__}, '
                        f'expected: {AwsCollectRequest.__name__} or {AzureCollectRequest.__name__}')

    return output_path
