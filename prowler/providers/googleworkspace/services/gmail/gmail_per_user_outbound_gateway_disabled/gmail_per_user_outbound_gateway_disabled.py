from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.gmail.gmail_client import gmail_client


class gmail_per_user_outbound_gateway_disabled(Check):
    """Check that per-user outbound gateways are disabled.

    This check verifies that the domain-level Gmail policy prevents users
    from sending mail through external SMTP servers, ensuring all outbound
    email passes through the organization's mail infrastructure.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if gmail_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=gmail_client.provider.domain_resource,
            )

            gateway_allowed = gmail_client.policies.allow_per_user_outbound_gateway

            if gateway_allowed is False:
                report.status = "PASS"
                report.status_extended = (
                    f"Per-user outbound gateways are disabled "
                    f"in domain {gmail_client.provider.identity.domain}."
                )
            elif gateway_allowed is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Per-user outbound gateways use Google's secure default "
                    f"configuration (disabled) "
                    f"in domain {gmail_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Per-user outbound gateways are enabled "
                    f"in domain {gmail_client.provider.identity.domain}. "
                    f"External SMTP server usage should be disabled."
                )

            findings.append(report)

        return findings
