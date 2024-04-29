from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.account.account_client import account_client


class account_maintain_different_contact_details_to_security_billing_and_operations(
    Check
):
    def execute(self):
        findings = []
        if account_client.contact_base:
            report = Check_Report_AWS(self.metadata())
            report.region = account_client.region
            report.resource_id = account_client.audited_account
            report.resource_arn = account_client.audited_account_arn

            if (
                len(account_client.contact_phone_numbers)
                == account_client.number_of_contacts
                and len(account_client.contact_names)
                == account_client.number_of_contacts
                # This is because the primary contact has no email field
                and len(account_client.contact_emails)
                == account_client.number_of_contacts - 1
            ):
                report.status = "PASS"
                report.status_extended = "SECURITY, BILLING and OPERATIONS contacts found and they are different between each other and between ROOT contact."
            else:
                report.status = "FAIL"
                report.status_extended = "SECURITY, BILLING and OPERATIONS contacts not found or they are not different between each other and between ROOT contact."
            findings.append(report)
        return findings
