import argparse
import os
import traceback

from dragoneye import collect, AzureCollectRequest
from dragoneye.collect_requests.aws_collect_request import AwsCollectRequest


def _add_aws_args(parser):
    sub = parser.add_subparsers(dest='auth-method', required=True)

    collect_by_assume_role = sub.add_parser('assume-role', help='Collect data by assuming a role')
    collect_by_access_key = sub.add_parser('access-key', help='Collect data using an access-key')

    _add_parser_arguments_for_assume_role(collect_by_assume_role)
    _add_parser_arguments_for_access_key(collect_by_access_key)


def _add_parser_arguments_for_assume_role(parser):
    parser.add_argument(
        "--account",
        help="Account to collect from",
        required=False,
        type=str,
        default='default',
        dest="account_name",
    )
    parser.add_argument(
        "--clean",
        help="Remove any existing data for the account before gathering",
        action="store_true",
    )
    parser.add_argument(
        "--max-attempts",
        help="Override Botocore config max_attempts (default 4)",
        required=False,
        type=int,
        dest="max_attempts",
        default=4
    )
    parser.add_argument(
        "--account-id",
        help="The account id to collect data from",
        required=True,
        type=str,
        dest="account_id"
    )
    parser.add_argument(
        "--external-id",
        help="The assume role external id",
        required=True,
        type=str,
        dest="external_id"
    )
    parser.add_argument(
        "--role-name",
        help="The AssumeRole role name",
        required=True,
        type=str,
        dest="role_name"
    )
    parser.add_argument(
        "--duration-session-time",
        help="the duration for the generated credential",
        required=False,
        type=int,
        dest="duration_session_time",
        default=3600
    )
    parser.add_argument(
        "--regions",
        help="Filter and query AWS only for the given regions (CSV)",
        required=False,
        type=str,
        dest="regions_filter",
        default=""
    )
    parser.add_argument(
        "--max-pool-connections",
        help="Override Botocore config max_pool_connections (default 10)",
        required=False,
        type=int,
        dest="max_pool_connections",
        default=10
    )
    parser.add_argument(
        "--command-timeout",
        help="The number of seconds before terminating a command (default 600)",
        required=False,
        type=int,
        dest="command_timeout",
        default=600
    )
    parser.add_argument(
        '-hidden-arg',
        dest='assume_role',
        default=True,
        help=argparse.SUPPRESS
    )
    parser.add_argument(
        '--output-path',
        dest='output_path',
        required=False,
        type=str,
        default=os.getcwd(),
        help='The path in which the collect results will be saved on. Defaults to current working directory.'
    )
    parser.add_argument(
        '--commands-path',
        dest='commands_path',
        required=True,
        type=str,
        help='The file path to the yaml file that contains all the commands to run'
    )


def _add_parser_arguments_for_access_key(parser):
    parser.add_argument(
        "--account",
        help="Account to collect from",
        required=False,
        type=str,
        default='default',
        dest="account_name",
    )
    parser.add_argument(
        "--profile",
        help="AWS profile name",
        required=False,
        type=str,
        dest="profile_name",
    )
    parser.add_argument(
        "--clean",
        help="Remove any existing data for the account before gathering",
        action="store_true",
    )
    parser.add_argument(
        "--max-attempts",
        help="Override Botocore config max_attempts (default 4)",
        required=False,
        type=int,
        dest="max_attempts",
        default=4
    )
    parser.add_argument(
        "--regions",
        help="Filter and query AWS only for the given regions (CSV)",
        required=False,
        type=str,
        dest="regions_filter",
        default=""
    )
    parser.add_argument(
        "--max-pool-connections",
        help="Override Botocore config max_pool_connections (default 10)",
        required=False,
        type=int,
        dest="max_pool_connections",
        default=10
    )
    parser.add_argument(
        "--command-timeout",
        help="The number of seconds before terminating a command (default 600)",
        required=False,
        type=int,
        dest="command_timeout",
        default=600
    )
    parser.add_argument(
        '-hidden-arg',
        dest='assume_role',
        default=False,
        help=argparse.SUPPRESS
    )
    parser.add_argument(
        '--output-path',
        dest='output_path',
        required=False,
        type=str,
        default=os.getcwd(),
        help='The path in which the collect results will be saved on. Defaults to current working directory.'
    )
    parser.add_argument(
        '--commands-path',
        dest='commands_path',
        required=True,
        type=str,
        help='The file path to the yaml file that contains all the commands to run'
    )
    parser.add_argument(
        "--duration-session-time",
        help="the duration for the generated credential",
        required=False,
        type=int,
        dest="duration_session_time",
        default=3600
    )


def _add_azure_args(parser):
    parser.add_argument(
        "--account",
        help="Account to collect from",
        required=False,
        type=str,
        default='default',
        dest="account_name",
    )
    parser.add_argument(
        "--clean",
        help="Remove any existing data for the account before gathering",
        action="store_true",
    )
    parser.add_argument(
        "--tenant-id",
        help="The tenant id to collect data from",
        required=True,
        type=str,
        dest="tenant_id"
    )
    parser.add_argument(
        "--subscription-id",
        help="The subscription id to collect data from",
        required=True,
        type=str,
        dest="subscription_id"
    )
    parser.add_argument(
        "--client-id",
        help="The client id to collect data from",
        required=True,
        type=str,
        dest="client_id"
    )
    parser.add_argument(
        "--client-secret",
        help="The tenant id to collect data from",
        required=True,
        type=str,
        dest="client_secret"
    )
    parser.add_argument(
        '--output-path',
        dest='output_path',
        required=False,
        type=str,
        default=os.getcwd(),
        help='The path in which the collect results will be saved on. Defaults to current working directory.'
    )
    parser.add_argument(
        '--commands-path',
        dest='commands_path',
        required=True,
        type=str,
        help='The file path to the yaml file that contains all the commands to run'
    )


def cli():
    try:
        prog = 'dragoneye'
        root_usage = '%(prog)s [provider] [options]\n\n' \
                'Examples:\n\n' \
                '%(prog)s azure [options]\n' \
                '%(prog)s aws assume-role [options]\n' \
                '%(prog)s aws access-key [options]\n'

        parser = argparse.ArgumentParser(description='A tool that collects data from the cloud', usage=root_usage, prog=prog)
        sub = parser.add_subparsers(dest='provider', required=True, help='Choose cloud provider', prog=prog)

        aws_collect = sub.add_parser('aws', help='Collect data from AWS')
        azure_collect = sub.add_parser('azure', help='Collect data from Azure')

        _add_aws_args(aws_collect)
        _add_azure_args(azure_collect)

        args = parser.parse_args()

        if args.provider == 'aws':
            request = AwsCollectRequest.from_args(args)
        else:
            request = AzureCollectRequest.from_args(args)

        output_path = collect(request)
        print(f'Results saved to: {output_path}')
    except Exception as ex:
        print('Error occurred while running dragoneye:')
        print(str(ex))
        traceback.print_tb(ex.__traceback__, limit=None, file=None)


if __name__ == '__main__':
    cli()
