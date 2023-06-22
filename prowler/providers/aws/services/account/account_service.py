from prowler.providers.aws.aws_provider import (
    generate_regional_clients,
    get_default_region,
)


################## Account
class Account:
    def __init__(self, audit_info):
        self.service = "account"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audited_partition = audit_info.audited_partition
        self.audited_account_arn = audit_info.audited_account_arn
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.region = get_default_region(audit_info)

    def __get_session__(self):
        return self.session


### This service don't need boto3 calls
