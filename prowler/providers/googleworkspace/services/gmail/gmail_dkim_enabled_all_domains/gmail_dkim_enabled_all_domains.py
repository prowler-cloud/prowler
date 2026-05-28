from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.gmail.gmail_client import gmail_client


class gmail_dkim_enabled_all_domains(Check):
    """Verify that DKIM is enabled for all mail-enabled domains.

    DKIM (DomainKeys Identified Mail) adds a cryptographic signature to
    outgoing messages, allowing receivers to verify authenticity and integrity.
    Because there is no public Admin SDK/API endpoint to query DKIM status,
    this check always returns MANUAL and directs the administrator to verify
    DKIM configuration in the Google Admin Console and via DNS lookup.

    - MANUAL: DKIM authentication status must be verified manually in the
      Admin Console and through DNS TXT record inspection for each domain.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        """Execute the DKIM enabled check.

        Returns:
            A list of reports with MANUAL status requiring administrator
            verification of DKIM configuration per domain.
        """
        findings = []

        report = CheckReportGoogleWorkspace(
            metadata=self.metadata(),
            resource=gmail_client.policies,
            resource_id="gmailPolicies",
            resource_name="Gmail Policies",
            customer_id=gmail_client.provider.identity.customer_id,
        )

        report.status = "MANUAL"
        report.status_extended = (
            f"DKIM authentication status for domain "
            f"{gmail_client.provider.identity.domain} cannot be automatically "
            f"verified because no public Admin SDK/API endpoint exposes this "
            f"setting. Verify in the Admin Console under Apps > Google "
            f"Workspace > Gmail > Authenticate email that DKIM signing is "
            f"generated and authentication is started for every mail-enabled "
            f"domain, and confirm via DNS that a valid TXT record exists at "
            f"google._domainkey.{gmail_client.provider.identity.domain}."
        )

        findings.append(report)

        return findings
