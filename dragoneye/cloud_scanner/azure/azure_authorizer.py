import json

import requests

from dragoneye.cloud_scanner.azure.azure_scan_request import AzureCredentials
from dragoneye.dragoneye_exception import DragoneyeException


class AzureAuthorizer:
    @staticmethod
    def get_authorization_token(credentials: AzureCredentials) -> str:
        response = requests.post(
            url=f'https://login.microsoftonline.com/{credentials.tenant_id}/oauth2/token',
            data={
                'grant_type': 'client_credentials',
                'client_id': credentials.client_id,
                'client_secret': credentials.client_secret,
                'resource': 'https://management.azure.com/'
            }
        )

        if response.status_code != 200:
            raise DragoneyeException(f'Failed to authenticate. status code: {response.status_code}\n'
                                     f'Reason: {response.text}')

        response_body = json.loads(response.text)
        access_token = response_body['access_token']
        return f'Bearer {access_token}'
