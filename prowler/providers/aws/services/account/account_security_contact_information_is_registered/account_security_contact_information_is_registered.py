from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.account.account_client import account_client

# This check has no findings since it is manual


class account_security_contact_information_is_registered(Check):
    def execute(self):
        report = Check_Report_AWS(self.metadata())
        report.region = account_client.region
        report.resource_id = account_client.audited_account
        report.status = "INFO"
        report.status_extended = "Manual check: Login to the AWS Console. Choose your account name on the top right of the window -> My Account -> Alternate Contacts -> Security Section."
        return [report]
