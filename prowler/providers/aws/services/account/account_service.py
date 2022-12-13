################## Account
from prowler.providers.aws.aws_provider import get_region_global_service


class Account:
    def __init__(self, audit_info):
        self.service = "account"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.region = get_region_global_service(audit_info)

    def __get_session__(self):
        return self.session


### This service don't need boto3 calls
