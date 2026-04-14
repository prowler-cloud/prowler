from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.gmail.gmail_client import gmail_client


class gmail_external_image_scanning_enabled(Check):
    """Check that scanning of linked images for malicious content is enabled.

    This check verifies that Gmail is configured to scan images linked
    in emails to detect and block malicious content hidden within
    external image resources.
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

            scanning_enabled = gmail_client.policies.enable_external_image_scanning

            if scanning_enabled is True:
                report.status = "PASS"
                report.status_extended = (
                    f"Scanning of linked images for malicious content is enabled "
                    f"in domain {gmail_client.provider.identity.domain}."
                )
            elif scanning_enabled is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Scanning of linked images for malicious content uses Google's "
                    f"secure default configuration (enabled) "
                    f"in domain {gmail_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Scanning of linked images for malicious content is disabled "
                    f"in domain {gmail_client.provider.identity.domain}. "
                    f"External image scanning should be enabled to detect hidden threats."
                )

            findings.append(report)

        return findings
