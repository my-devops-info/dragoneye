import os


class AwsUtils:
    @staticmethod
    def get_default_region() -> str:
        default_region = os.environ.get("AWS_REGION", "us-east-1")
        if 'gov-' in default_region:
            default_region = 'us-gov-west-1'
        elif 'cn-' in default_region:
            default_region = 'cn-north-1'
        else:
            default_region = 'us-east-1'
        return default_region

    @staticmethod
    def get_api_region() -> str:
        return os.environ.get("AWS_REGION", "us-east-1")
