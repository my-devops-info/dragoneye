from .collect_requests.azure_collect_request import AzureCollectRequest
from .collect_requests.aws_collect_request import AwsAccessKeyCollectRequest, AwsAssumeRoleCollectRequest
# pylint: disable=cyclic-import
from .runner import collect
