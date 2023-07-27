################## Account
from prowler.providers.aws.lib.service.service import AWS_Service


class Account(AWS_Service):
    def __init__(self, audit_info):
        # Call AWS_Service's __init__
        super().__init__(__class__.__name__, audit_info)

    def __get_session__(self):
        return self.session


### This service don't need boto3 calls
