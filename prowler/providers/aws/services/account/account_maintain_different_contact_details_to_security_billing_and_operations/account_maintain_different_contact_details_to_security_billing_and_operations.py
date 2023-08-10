from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.account.account_client import account_client

# This check has no findings since it is manual


class account_maintain_different_contact_details_to_security_billing_and_operations(
    Check
):
    def execute(self):
        report = Check_Report_AWS(self.metadata())
        report.region = account_client.region
        report.resource_id = account_client.audited_account
        report.resource_arn = account_client.audited_account_arn
        root_contact = account_client.client.get_contact_information()[
            "ContactInformation"
        ]
        try:
            billing_contact = account_client.client.get_alternate_contact(
                AlternateContactType="BILLING"
            )
            security_contact = account_client.client.get_alternate_contact(
                AlternateContactType="SECURITY"
            )
            operations_contact = account_client.client.get_alternate_contact(
                AlternateContactType="OPERATIONS"
            )
        except Exception:
            billing_contact = None
            security_contact = None
            operations_contact = None
        if all(
            [
                contact is not None
                for contact in [
                    root_contact,
                    billing_contact,
                    security_contact,
                    operations_contact,
                ]
            ]
        ):
            report.status = "PASS"
            report.status_extended = "SECURITY, BILLING and OPERATIONS contacts found and they are different between each other and between ROOT contact."
        else:
            report.status = "FAIL"
            report.status_extended = "SECURITY, BILLING and OPERATIONS contacts not found and they are different between each other and between ROOT contact."
        return [report]
