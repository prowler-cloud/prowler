from prowler.lib.check.models import Check, CheckReportOracledb
from prowler.providers.oracledb.services.audit.audit_client import audit_client


class audit_trail_enabled(Check):
    """Check that database auditing is enabled."""

    def execute(self) -> list[CheckReportOracledb]:
        """Execute the check logic.

        Returns:
            A single report for the audited database.
        """
        findings = []
        report = CheckReportOracledb(
            metadata=self.metadata(),
            resource={},
            resource_name=audit_client.database_name,
            resource_id=audit_client.database_name,
        )
        audit_trail = (audit_client.audit_trail or "NONE").upper()
        if audit_client.unified_auditing:
            report.status = "PASS"
            report.status_extended = (
                f"Database {audit_client.database_name} has Unified "
                "Auditing enabled."
            )
        elif audit_trail != "NONE":
            report.status = "PASS"
            report.status_extended = (
                f"Database {audit_client.database_name} has traditional "
                f"auditing enabled (AUDIT_TRAIL={audit_trail})."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                f"Database {audit_client.database_name} has auditing "
                "disabled (AUDIT_TRAIL=NONE and no Unified Auditing)."
            )
        findings.append(report)
        return findings
