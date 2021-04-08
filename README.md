![Dragoneye](dragoneye_header.png)

![CD](https://github.com/indeni/dragoneye/actions/workflows/cd.yaml/badge.svg) 

# dragoneye
dragoneye is a Python tool that is used to collect data about a cloud environment using the cloud provider's APIs. It is intended to function as component in other tools who have the need to collect data quickly, with high performance, and within API quotas.

dragoneye currently supports AWS (AssumeRole and AccessKey based collection) and Azure (with client secret).

# Setup
Clone this git repository, navigate to the root directory where `setup.py` is located and run:
```
pip install .
```
(note the period at the end of the command)

We recommend doing this within a virtual environment, like so:
```
python3.9 -m venv ./venv
. ./venv/bin/activate
pip install .
```

# Usage

## Programmatic Usage
Create an instance of one of the CollectRequest classes, such as AwsAccessKeyCollectRequest, AwsAssumeRoleCollectRequest, AzureCollectRequest and call the `collect` function. For example:
```
from dragoneye import collect, AwsAccessKeyCollectRequest, AzureCollectRequest, AwsAssumeRoleCollectRequest

aws_access_key_request = AwsAccessKeyCollectRequest(
   account_name='...',
   account_id='...',
   regions_filter=['us-east-1'],)

aws_assume_role_request = AwsAssumeRoleCollectRequest(
   account_id='...',
   account_name='...',
   external_id='...',
   role_name='...')

azure_collect_request = AzureCollectRequest(
   account_name='...',
   tenant_id='...',
   subscription_id='...',
   client_id='...',
   client_secret='...',
   clean=True
)

collect(azure_collect_request)  # Returns the path to the directory that holds the results
```

## CLI usage

### For collecting data from AWS with an AccessKey
```
dragoneye aws access-key [options]
```

### For collecting data from AWS with AssumeRole
```
dragoneye aws assume-role [options]
```

### For collecting data from Azure with a client secret
```
dragoneye azure [options]
```
