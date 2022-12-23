################## Account


class Account:
    def __init__(self, audit_info):
        self.service = "account"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.region = audit_info.profile_region

    def __get_session__(self):
        return self.session


### This service don't need boto3 calls
