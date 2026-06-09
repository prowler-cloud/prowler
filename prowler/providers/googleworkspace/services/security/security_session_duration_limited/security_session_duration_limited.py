from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.lib.logger import logger
from prowler.providers.googleworkspace.services.security.security_client import (
    security_client,
)

MAX_SESSION_DURATION_SECONDS = 43200  # 12 hours


class security_session_duration_limited(Check):
    """Check that Google session control is configured to 12 hours or less.

    This check verifies that the domain-level web session duration is set
    to 12 hours or less, requiring users to re-authenticate more frequently
    than the default 14-day session length.
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

            duration_str = security_client.policies.web_session_duration
            domain = security_client.provider.identity.domain

            if duration_str is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"Google session control is not explicitly configured "
                    f"in domain {domain}. The default is 14 days. "
                    f"Web session duration should be 12 hours or less."
                )
                findings.append(report)
                return findings

            try:
                duration_seconds = int(duration_str.removesuffix("s"))
            except ValueError:
                logger.error(f"Unparseable web session duration: {duration_str!r}")
                report.status = "FAIL"
                report.status_extended = (
                    f"Web session duration value {duration_str!r} is not parseable "
                    f"in domain {domain}."
                )
                findings.append(report)
                return findings

            duration_hours = duration_seconds / 3600

            if duration_seconds <= MAX_SESSION_DURATION_SECONDS:
                report.status = "PASS"
                report.status_extended = (
                    f"Google session control is set to {duration_hours:.0f} hours "
                    f"in domain {domain}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Google session control is set to {duration_hours:.0f} hours "
                    f"in domain {domain}. "
                    f"Web session duration should be 12 hours or less."
                )

            findings.append(report)

        return findings
