from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.exchange.exchange_client import exchange_client

class exchange_mailbox_primary_smtp_uses_custom_domain(Check):
    """
    Verify that every Exchange Online mailbox uses a verified custom domain 
    as its primary SMTP address, not the default .onmicrosoft.com domain
    
    The .onmicrosoft.com domain is assigned by Microsoft on tenant creation
    and is not intended for ongoing mail. Mailboxes still using it leak the
    internal tenant identifier in every From: header (aiding spear-phishing), 
    bypass DMARC/DKIM hardening on custom domains and are often treated as 
    low-trust by recipient anti-phishing engines.

    - PASS: Primary SMTP address uses a verified custom domain.
    - FAIL: Primary SMTP address uses the .onmicrosoft.com domain.
    - MANUAL: Exchange Online PowerShell unavailable; check cannot run.
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check against all recipient-facing Exchange Online mailboxes.

        Returns:
            List[CheckReportM365]: A report for each mailbox with 
                its SMTP domain status
        """
        findings = []

        # MANUAL case: if the mailboxes list if empty it mean Powershell
        # couldn't connect and no data was retrieved
        if not exchange_client.mailboxes:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={}, 
                resource_name="Exchange Online Mailboxes", 
                resource_id="exchange_mailboxes", 
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Exchange Online PowerShell is unavailable. "
                "Enable EXO PowerShell access to run this check."
            )
            findings.append(report)
            return findings

        for mailbox in exchange_client.mailboxes:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=mailbox, 
                resource_name=mailbox.name or mailbox.identity, 
                resource_id=mailbox.identity,
            )

            # Core check: does the primary SMTP address end with .onmicrosoft.com?
            if mailbox.primary_smtp_address.endswith(".onmicrosoft.com"):
                report.status = "FAIL"
                report.status_extended = (
                    f"Mailbox {mailbox.identity} "
                    f"({mailbox.recipient_type_details}) has primary SMTP "
                    f"address {mailbox.primary_smtp_address} using the "
                    f".onmicrosoft.com domain instead of a verified custom domain."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Mailbox {mailbox.identity} "
                    f"({mailbox.recipient_type_details}) has primary SMTP "
                    f"address {mailbox.primary_smtp_address} using a "
                    f"verified custom domain."
                )

            findings.append(report)

        return findings