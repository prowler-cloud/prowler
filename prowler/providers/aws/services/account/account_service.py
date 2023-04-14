from prowler.providers.aws.aws_provider import generate_regional_clients


################## Account
class Account:
    def __init__(self, audit_info):
        self.service = "account"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        # If the region is not set in the audit profile,
        # we pick the first region from the regional clients list
        self.region = (
            audit_info.profile_region
            if audit_info.profile_region
            else list(self.regional_clients.keys())[0]
        )

    def __get_session__(self):
        return self.session


### This service don't need boto3 calls
