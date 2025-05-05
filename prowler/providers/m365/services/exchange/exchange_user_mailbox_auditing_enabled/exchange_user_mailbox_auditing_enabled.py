from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.exchange.exchange_client import exchange_client
from prowler.providers.m365.services.exchange.exchange_service import (
    AuditAdmin,
    AuditDelegate,
    AuditOwner,
)


class exchange_user_mailbox_auditing_enabled(Check):
    """
    Check to ensure mailbox auditing is enabled for all user mailboxes.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check to validate that mailbox auditing is enabled for all user mailboxes.

        This method retrieves all mailbox audit properties from the Exchange service and evaluates
        whether auditing is enabled and correctly configured for each mailbox. A report is generated
        for each mailbox.

        Returns:
            List[CheckReportM365]: A list of findings with the status of each mailbox.
        """
        findings = []

        required_admin = {e.value for e in AuditAdmin}
        required_delegate = {e.value for e in AuditDelegate}
        required_owner = {e.value for e in AuditOwner}

        for mailbox in exchange_client.mailbox_audit_properties:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=mailbox,
                resource_name=mailbox.name,
                resource_id=mailbox.identity,
            )

            report.status = "FAIL"
            report.status_extended = (
                f"Mailbox Audit Properties for Mailbox {mailbox.name} is not enabled."
            )

            if mailbox.audit_enabled:
                audit_admin = set(mailbox.audit_admin or [])
                audit_delegate = set(mailbox.audit_delegate or [])
                audit_owner = set(mailbox.audit_owner or [])

                if (
                    required_admin.issubset(audit_admin)
                    and required_delegate.issubset(audit_delegate)
                    and required_owner.issubset(audit_owner)
                ):
                    if mailbox.audit_log_age >= exchange_client.audit_config.get(
                        "audit_log_age", 90
                    ):
                        report.status = "PASS"
                        report.status_extended = f"Mailbox Audit Properties for Mailbox {mailbox.name} is enabled with an audit log age of {mailbox.audit_log_age} days."
                    else:
                        report.status_extended = f"Mailbox Audit Properties for Mailbox {mailbox.name} is enabled but the audit log age is less than {exchange_client.audit_config.get('audit_log_age', 90)} days ({mailbox.audit_log_age} days)."
                else:
                    report.status_extended = f"Mailbox Audit Properties for Mailbox {mailbox.name} is enabled but without all audit actions configured."

            findings.append(report)

        return findings
