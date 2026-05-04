from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.gmail.gmail_client import gmail_client


class gmail_groups_spoofing_protection_enabled(Check):
    """Check that groups are protected from inbound emails spoofing your domain.

    This check verifies that Gmail is configured to take action on
    inbound emails to groups that spoof the organization's domain,
    helping prevent impersonation attacks targeting group mailboxes.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if gmail_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=gmail_client.provider.domain_resource,
            )

            enabled = gmail_client.policies.detect_groups_spoofing
            consequence = gmail_client.policies.groups_spoofing_consequence

            if enabled is False:
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection of groups from inbound emails spoofing your "
                    f"domain is disabled in domain "
                    f"{gmail_client.provider.identity.domain}. "
                    f"Enable the protection and configure a protective action."
                )
            elif enabled is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection of groups from inbound emails spoofing your "
                    f"domain is not configured and uses Google's insecure "
                    f"default (disabled) in domain "
                    f"{gmail_client.provider.identity.domain}. "
                    f"Enable the protection and configure a protective action."
                )
            elif consequence == "NO_ACTION":
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection of groups from inbound emails spoofing your "
                    f"domain is set to take no action in domain "
                    f"{gmail_client.provider.identity.domain}. "
                    f"A protective action should be configured."
                )
            elif consequence is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Protection of groups from inbound emails spoofing your "
                    f"domain is enabled in domain "
                    f"{gmail_client.provider.identity.domain}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Protection of groups from inbound emails spoofing your "
                    f"domain is enabled with consequence '{consequence}' "
                    f"in domain {gmail_client.provider.identity.domain}."
                )

            findings.append(report)

        return findings
