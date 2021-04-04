import argparse
import sys
import traceback

from dragoneye import collect

from dragoneye.collectors.aws_collect_tool.aws_collect_tool import AwsCollectTool
from dragoneye.collectors.azure_collect_tool.azure_collect_tool import AzureCollectTool


def cli():
    try:
        usage_msg = 'dragoneye [provider] [options]\n' \
                    'To see the help text, you can run:\n\n' \
                    'dragoneye --help\n'
        usage_msg = '# THE CUSTOM USAGE MESSAGE #'
        parser = argparse.ArgumentParser(description='A tool that collects data from the cloud')
        sub = parser.add_subparsers(dest='provider', required=True, help='Choose cloud provider')

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
        output_path = collect(request)
        print(f'Results saved to: {output_path}')
    except Exception as ex:
        print('Error occurred while running dragoneye:')
        print(str(ex))
        traceback.print_tb(ex.__traceback__, limit=None, file=None)


if __name__ == '__main__':
    cli()
