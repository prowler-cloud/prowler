from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.lib.licensing import (
    DRIVE_DLP_EXPLANATION,
    EDITIONS_WITHOUT_DRIVE_DLP,
    edition_reason_suffix,
)
from prowler.providers.googleworkspace.services.security.security_client import (
    security_client,
)


class security_dlp_drive_rules_configured(Check):
    """Check that DLP policies for Google Drive are configured.

    This check verifies that at least one active Data Loss Prevention (DLP)
    rule targeting Google Drive file sharing exists, helping to prevent
    unintended exposure of sensitive information. DLP for Drive is
    edition-gated: when every edition the tenant holds lacks it, the finding
    says so. A Cloud Identity Premium subscription counts as holding it.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if security_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=security_client.policies,
                resource_id="securityPolicies",
                resource_name="Security Policies",
                customer_id=security_client.provider.identity.customer_id,
            )

            dlp_exists = security_client.policies.dlp_drive_rules_exist
            domain = security_client.provider.identity.domain

            if dlp_exists is True:
                report.status = "PASS"
                report.status_extended = (
                    f"DLP policies for Google Drive are configured "
                    f"in domain {domain}. At least one active DLP rule "
                    f"targeting Drive file sharing exists."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"No active DLP policies for Google Drive are configured "
                    f"in domain {domain}. DLP rules should be configured "
                    f"to detect and prevent sharing of sensitive information "
                    f"through Drive."
                    f"{edition_reason_suffix(security_client.provider.editions, EDITIONS_WITHOUT_DRIVE_DLP, DRIVE_DLP_EXPLANATION)}"
                )

            findings.append(report)

        return findings
