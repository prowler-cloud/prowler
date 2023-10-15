from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.account.account_client import account_client


class account_maintain_different_contact_details_to_security_billing_and_operations(
    Check
):
    def execute(self):
        report = Check_Report_AWS(self.metadata())
        report.region = account_client.region
        report.resource_id = account_client.audited_account
        report.resource_arn = account_client.audited_account_arn

        contacts_list = account_client.contacts.get_contacts_list()
        if all(
            [contact is not None for contact in contacts_list]
            and len(set(contacts_list)) == len(contacts_list)
        ):
            report.status = "PASS"
            report.status_extended = "SECURITY, BILLING and OPERATIONS contacts found and they are different between each other and between ROOT contact."
        else:
            report.status = "FAIL"
            report.status_extended = "SECURITY, BILLING and OPERATIONS contacts not found or they are not different between each other and between ROOT contact."
        return [report]
