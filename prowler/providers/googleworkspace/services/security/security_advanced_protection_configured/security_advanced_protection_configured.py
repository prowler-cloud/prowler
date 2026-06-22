from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.security.security_client import (
    security_client,
)


class security_advanced_protection_configured(Check):
    """Check that the Advanced Protection Program is configured.

    This check verifies that the domain-level policy enables Advanced
    Protection Program self-enrollment and blocks the use of security codes,
    as recommended by CIS 4.1.3.1.
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

            enrollment = security_client.policies.advanced_protection_enrollment
            code_option = (
                security_client.policies.advanced_protection_security_code_option
            )
            domain = security_client.provider.identity.domain

            enrollment_ok = enrollment is True
            codes_ok = code_option == "CODES_NOT_ALLOWED"

            if enrollment_ok and codes_ok:
                report.status = "PASS"
                report.status_extended = (
                    f"Advanced Protection Program is configured with enrollment "
                    f"enabled and security codes blocked in domain {domain}."
                )
            else:
                report.status = "FAIL"
                issues = []
                if not enrollment_ok:
                    issues.append(
                        "enrollment is not configured"
                        if enrollment is None
                        else "enrollment is disabled"
                    )
                if not codes_ok:
                    issues.append(
                        f"security codes are "
                        f"{code_option or 'using default (allowed without remote access)'} "
                        f"(should be CODES_NOT_ALLOWED)"
                    )
                report.status_extended = (
                    f"Advanced Protection Program is not properly configured "
                    f"in domain {domain}: {'; '.join(issues)}."
                )

            findings.append(report)

        return findings
