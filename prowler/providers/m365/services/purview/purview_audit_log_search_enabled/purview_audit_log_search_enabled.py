from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.purview.purview_client import purview_client


class purview_audit_log_search_enabled(Check):
    """Check if Purview audit log search is enabled.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for audit log search

        This method checks if audit log search is enabled Purview settings

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        audit_log_config = purview_client.audit_log_config
        report = CheckReportM365(
            metadata=self.metadata(),
            resource=audit_log_config if audit_log_config else {},
            resource_name="Purview Settings",
            resource_id="purviewSettings",
        )
        report.status = "FAIL"
        report.status_extended = "Purview audit log search is not enabled."

        if purview_client.audit_log_config and getattr(
            purview_client.audit_log_config, "audit_log_search", False
        ):
            report.status = "PASS"
            report.status_extended = "Purview audit log search is enabled."

        findings.append(report)

        return findings
