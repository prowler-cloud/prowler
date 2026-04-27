from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.gmail.gmail_client import gmail_client


class gmail_auto_forwarding_disabled(Check):
    """Check that automatic forwarding options are disabled.

    This check verifies that the domain-level Gmail policy prevents users
    from automatically forwarding incoming email to external addresses,
    reducing the risk of data exfiltration.
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

            forwarding_enabled = gmail_client.policies.enable_auto_forwarding

            if forwarding_enabled is False:
                report.status = "PASS"
                report.status_extended = (
                    f"Automatic email forwarding is disabled "
                    f"in domain {gmail_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                if forwarding_enabled is None:
                    report.status_extended = (
                        f"Automatic email forwarding is not explicitly configured "
                        f"in domain {gmail_client.provider.identity.domain}. "
                        f"Auto-forwarding should be disabled to prevent data exfiltration."
                    )
                else:
                    report.status_extended = (
                        f"Automatic email forwarding is enabled "
                        f"in domain {gmail_client.provider.identity.domain}. "
                        f"Auto-forwarding should be disabled to prevent data exfiltration."
                    )

            findings.append(report)

        return findings
