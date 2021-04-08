from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from dragoneye.cloud_scanner.aws.aws_scan_request import AwsCredentials
from dragoneye.dragoneye_exception import DragoneyeException


class AwsSessionFactory:
    @staticmethod
    def get_session(credentials: AwsCredentials,
                    region: Optional[str] = None):
        if credentials.account_id and credentials.role_name and credentials.external_id:
            # use assume rule
            session = AwsSessionFactory._get_session_using_assume_role(credentials.account_id,
                                                                       credentials.role_name,
                                                                       credentials.external_id,
                                                                       credentials.session_duration,
                                                                       region)
        else:
            session_data = {}
            if region:
                session_data["region_name"] = region
            if credentials.profile_name:
                session_data["profile_name"] = credentials.profile_name
            session = boto3.Session(**session_data)
        AwsSessionFactory.test_connectivity(session)
        return session

    @staticmethod
    def _get_session_using_assume_role(account_id, role_name, external_id, session_duration, region):
        role_arn = "arn:aws:iam::" + account_id + ":role/" + role_name
        role_session_name = "DragoneyeSession"
        # TODO: replace with logger
        print('will try to assume role using ARN: {} and external id {} for account {}'
              .format(role_arn, external_id, account_id))
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

        iam = session.client("iam")
        try:
            iam.get_user(UserName="CloudMapper")
        except ClientError as ex:
            if "InvalidClientTokenId" in str(ex):
                raise DragoneyeException(
                    "AWS doesn't allow you to make IAM calls from a session without MFA, and the collect command gathers IAM data.  "
                    "Please use MFA or don't use a session. With aws-vault, specify `--no-session` on your `exec`.", ex)
            if "NoSuchEntity" in str(ex):
                # Ignore, we're just testing that our credentials work
                pass
            else:
                raise DragoneyeException('Ensure your credentials are valid', ex)
        except NoCredentialsError as ex:
            raise DragoneyeException("No AWS credentials configured.", ex)
