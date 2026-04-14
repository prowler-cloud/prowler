from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.gmail.gmail_client import gmail_client


class gmail_enhanced_pre_delivery_scanning_enabled(Check):
    """Check that enhanced pre-delivery message scanning is enabled.

    This check verifies that Gmail is configured to perform additional
    security checks on suspicious messages before delivering them,
    improving detection of phishing and malware.
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

            scanning_enabled = (
                gmail_client.policies.enable_enhanced_pre_delivery_scanning
            )

            if scanning_enabled is True:
                report.status = "PASS"
                report.status_extended = (
                    f"Enhanced pre-delivery message scanning is enabled "
                    f"in domain {gmail_client.provider.identity.domain}."
                )
            elif scanning_enabled is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Enhanced pre-delivery message scanning uses Google's "
                    f"secure default configuration (enabled) "
                    f"in domain {gmail_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Enhanced pre-delivery message scanning is disabled "
                    f"in domain {gmail_client.provider.identity.domain}. "
                    f"Pre-delivery scanning should be enabled for improved threat detection."
                )

            findings.append(report)

        return findings
