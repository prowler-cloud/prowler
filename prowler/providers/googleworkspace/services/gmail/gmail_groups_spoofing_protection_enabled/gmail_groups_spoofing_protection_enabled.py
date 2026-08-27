from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.gmail.gmail_client import gmail_client
from prowler.providers.googleworkspace.services.gmail.lib.spoofing import (
    describe_consequence,
    is_protective,
)


class gmail_groups_spoofing_protection_enabled(Check):
    """Check that groups are protected from inbound emails spoofing your domain.

    This check verifies that Gmail is configured to take action on
    inbound emails to groups that spoof the organization's domain,
    helping prevent impersonation attacks targeting group mailboxes.
    CIS requires the configured action to move the message to spam, so an
    action that only shows a warning is reported as a failure.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if gmail_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=gmail_client.policies,
                resource_id="gmailPolicies",
                resource_name="Gmail Policies",
                customer_id=gmail_client.provider.identity.customer_id,
            )

            enabled = gmail_client.policies.detect_groups_spoofing
            consequence = gmail_client.policies.groups_spoofing_consequence
            visibility_type = gmail_client.policies.groups_spoofing_visibility_type
            domain = gmail_client.provider.identity.domain
            scope = (
                "private groups only"
                if visibility_type == "PRIVATE_GROUPS_ONLY"
                else "all groups"
            )

            if enabled is False:
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection of groups from inbound emails spoofing your "
                    f"domain is disabled in domain {domain}. "
                    f"Enable the protection and set the action to move the "
                    f"email to spam."
                )
            elif enabled is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection of groups from inbound emails spoofing your "
                    f"domain is not configured and uses Google's insecure "
                    f"default (disabled) in domain {domain}. "
                    f"Enable the protection and set the action to move the "
                    f"email to spam."
                )
            elif not is_protective(consequence):
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection of groups from inbound emails spoofing your "
                    f"domain is enabled for {scope} but "
                    f"{describe_consequence(consequence)} in domain {domain}. "
                    f"The action should move the email to spam."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Protection of groups from inbound emails spoofing your "
                    f"domain is enabled for {scope} with action "
                    f"'{consequence}' in domain {domain}."
                )

            findings.append(report)

        return findings
