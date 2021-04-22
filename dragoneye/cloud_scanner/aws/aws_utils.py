import os

from dragoneye.cloud_scanner.aws.aws_scan_settings import AwsRegionType


class AwsUtils:
    @staticmethod
    def get_default_region(region_type: AwsRegionType) -> str:
        default_region = os.environ.get('AWS_DEFAULT_REGION', os.environ.get('AWS_REGION'))
        if default_region:
            return default_region
        else:
            return AwsUtils.get_default_region_by_type(region_type)

    @staticmethod
    def get_default_region_by_type(region_type: AwsRegionType):
        _region_type = region_type.lower()
        if _region_type == AwsRegionType.Standard.value.lower():
            return 'us-east-1'
        if _region_type == AwsRegionType.Gov.value.lower():
            return 'us-gov-west-1'
        if _region_type == AwsRegionType.China.value.lower():
            return 'cn-north-1'

        possible_values = ', '.join([region.value for region in AwsRegionType])
        return ValueError(f'Unexpected region type. Possible values: {possible_values}, got: {region_type}')
