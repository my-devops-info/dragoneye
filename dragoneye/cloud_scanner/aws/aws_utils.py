import os


class AwsUtils:
    @staticmethod
    def get_default_region() -> str:
        return os.environ.get("AWS_REGION", "us-east-1")
