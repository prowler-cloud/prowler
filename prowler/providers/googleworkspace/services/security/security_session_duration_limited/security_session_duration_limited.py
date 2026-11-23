from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.lib.logger import logger
from prowler.providers.googleworkspace.lib.licensing import (
    EDITIONS_WITHOUT_SESSION_CONTROL,
    SESSION_CONTROL_EXPLANATION,
    edition_reason_suffix,
)
from prowler.providers.googleworkspace.services.security.security_client import (
    security_client,
)

MAX_SESSION_DURATION_SECONDS = 43200  # 12 hours


def _edition_suffix() -> str:
    """Read the editions only when a finding is about to carry the suffix.

    The provider reads the editions on first use, so a passing tenant never
    pays the Licensing API calls nor sees its authorization warning.
    """
    return edition_reason_suffix(
        security_client.provider.editions,
        EDITIONS_WITHOUT_SESSION_CONTROL,
        SESSION_CONTROL_EXPLANATION,
    )


class security_session_duration_limited(Check):
    """Check that Google session control is configured to 12 hours or less.

    This check verifies that the domain-level web session duration is set
    to 12 hours or less, requiring users to re-authenticate more frequently
    than the default 14-day session length. Google session control is
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

            duration_str = security_client.policies.web_session_duration
            domain = security_client.provider.identity.domain

            if duration_str is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"Google session control is not explicitly configured "
                    f"in domain {domain}. The default is 14 days. "
                    f"Web session duration should be 12 hours or less."
                    f"{_edition_suffix()}"
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
                    f"{_edition_suffix()}"
                )

            findings.append(report)

        return findings
