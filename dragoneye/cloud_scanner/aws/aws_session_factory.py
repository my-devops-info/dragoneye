from typing import Optional

import boto3
from botocore.exceptions import ClientError

from dragoneye.utils.app_logger import logger
from dragoneye.dragoneye_exception import DragoneyeException


class AwsSessionFactory:
    @staticmethod
    def get_session(profile_name: Optional[str] = None, region: Optional[str] = None):
        session_data = {}
        if region:
            session_data["region_name"] = region
        if profile_name:
            session_data["profile_name"] = profile_name
        session = boto3.Session(**session_data)
        AwsSessionFactory.test_connectivity(session)
        return session

    @staticmethod
    def get_session_using_assume_role(role_arn, external_id, region, session_duration=3600):
        role_session_name = "DragoneyeSession"
        logger.info('will try to assume role using ARN: {} and external id {}'.format(role_arn, external_id))
        client = boto3.client('sts')
        response = client.assume_role(RoleArn=role_arn,
                                      RoleSessionName=role_session_name,
                                      DurationSeconds=session_duration,
                                      ExternalId=external_id)
        credentials = response['Credentials']
        session = boto3.Session(aws_access_key_id=credentials['AccessKeyId'],
                                aws_secret_access_key=credentials['SecretAccessKey'],
                                aws_session_token=credentials['SessionToken'],
                                region_name=region)
        AwsSessionFactory.test_connectivity(session)
        return session

    @staticmethod
    def test_connectivity(session):
        sts = session.client("sts")
        try:
            sts.get_caller_identity()
        except ClientError as ex:
            if "InvalidClientTokenId" in str(ex):
                raise DragoneyeException('sts.get_caller_identity failed with InvalidClientTokenId. '
                                         'Likely cause is no AWS credentials are set', ex)
            raise DragoneyeException('Unknown exception when trying to call sts.get_caller_identity: {}'.format(ex), ex)
