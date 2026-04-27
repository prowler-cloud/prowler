from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.gmail.gmail_client import gmail_client


class gmail_comprehensive_mail_storage_enabled(Check):
    """Check that comprehensive mail storage is enabled.

    This check verifies that the domain-level Gmail policy ensures a copy
    of all sent and received mail is stored in users' Gmail mailboxes,
    making all messages accessible to Vault for compliance and eDiscovery.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if gmail_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=gmail_client.provider.identity,
                resource_name=gmail_client.provider.identity.domain,
                resource_id=gmail_client.provider.identity.customer_id,
                customer_id=gmail_client.provider.identity.customer_id,
                location="global",
            )

            storage_enabled = gmail_client.policies.comprehensive_mail_storage_enabled

            if storage_enabled is True:
                report.status = "PASS"
                report.status_extended = (
                    f"Comprehensive mail storage is enabled "
                    f"in domain {gmail_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                if storage_enabled is None:
                    report.status_extended = (
                        f"Comprehensive mail storage is not explicitly configured "
                        f"in domain {gmail_client.provider.identity.domain}. "
                        f"Comprehensive mail storage should be enabled for compliance."
                    )
                else:
                    report.status_extended = (
                        f"Comprehensive mail storage is disabled "
                        f"in domain {gmail_client.provider.identity.domain}. "
                        f"Comprehensive mail storage should be enabled for compliance."
                    )

            findings.append(report)

        return findings
