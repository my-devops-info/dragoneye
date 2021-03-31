import argparse

from dragoneye.collect_requests.aws_collect_request import AwsCollectRequest
from dragoneye.collect_requests.azure_collect_request import AzureCollectRequest
from dragoneye.collect_requests.collect_request import CollectRequest
from dragoneye.collectors.aws_collect_tool.aws_collect import AwsCollectTool
from dragoneye.collectors.azure_collect_tool.azure_collect_tool import AzureCollectTool


def collect(collect_request: CollectRequest) -> str:
    if isinstance(collect_request, AwsCollectRequest):
        return AwsCollectTool.collect(collect_request)
    elif isinstance(collect_request, AzureCollectRequest):
        return AzureCollectTool.collect(collect_request)
    else:
        raise Exception(f'Unknown collect request type. '
                        f'Got: {type(collect_request).__name__}, '
                        f'expected: {AwsCollectRequest.__name__} or {AzureCollectRequest.__name__}')


def cli():
    try:
        parser = argparse.ArgumentParser(description='Choose cloud provider')
        sub = parser.add_subparsers(dest='provider', required=True)

        aws_collect = sub.add_parser('aws', help='Collect data from AWS')
        azure_collect = sub.add_parser('azure', help='Collect data from Azure')

        AwsCollectTool.add_parser_args(aws_collect)
        AzureCollectTool.add_parser_args(azure_collect)

        args = parser.parse_args()

        if args.provider == 'aws':
            collect_tool = AwsCollectTool
        else:
            collect_tool = AzureCollectTool

        request = collect_tool.convert_args_to_request(args)
        collect_tool.collect(request)
    except Exception as ex:
        print('Error occurred while running dragoneye:')
        print(str(ex))


if __name__ == '__main__':
    cli()
