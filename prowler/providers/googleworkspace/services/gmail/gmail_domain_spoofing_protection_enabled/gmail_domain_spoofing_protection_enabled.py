from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.gmail.gmail_client import gmail_client
from prowler.providers.googleworkspace.services.gmail.lib.spoofing import (
    describe_consequence,
    is_protective,
)


class gmail_domain_spoofing_protection_enabled(Check):
    """Check that protection against domain spoofing based on similar domain names is enabled.

    This check verifies that Gmail is configured to take action on
    emails that appear to come from similar-looking domain names,
    helping prevent phishing via domain impersonation. CIS requires the
    configured action to move the message to spam, so an action that only
    shows a warning is reported as a failure.
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

            enabled = gmail_client.policies.detect_domain_name_spoofing
            consequence = gmail_client.policies.domain_spoofing_consequence
            domain = gmail_client.provider.identity.domain

            if enabled is False:
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection against domain spoofing based on similar domain names "
                    f"is disabled in domain {domain}. "
                    f"Enable the protection and set the action to move the "
                    f"email to spam."
                )
            elif not is_protective(consequence):
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection against domain spoofing based on similar domain names "
                    f"{describe_consequence(consequence)} in domain {domain}. "
                    f"The action should move the email to spam."
                )
            else:
                report.status = "PASS"
                state = "is enabled" if enabled else "uses Google's default (enabled)"
                report.status_extended = (
                    f"Protection against domain spoofing based on similar domain names "
                    f"{state} with action '{consequence}' in domain "
                    f"{domain}."
                )

            findings.append(report)

        return findings
