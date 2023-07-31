################## Account
from prowler.providers.aws.lib.service.service import AWSService


class Account(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, audit_info)


### This service don't need boto3 calls
