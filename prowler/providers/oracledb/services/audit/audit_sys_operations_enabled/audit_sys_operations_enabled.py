from prowler.lib.check.models import Check, CheckReportOracledb
from prowler.providers.oracledb.services.audit.audit_client import audit_client


class audit_sys_operations_enabled(Check):
    """Check that auditing of SYS administrative operations is enabled."""

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
        if (audit_client.audit_sys_operations or "").upper() == "TRUE":
            report.status = "PASS"
            report.status_extended = (
                f"Database {audit_client.database_name} audits SYS "
                "administrative operations (AUDIT_SYS_OPERATIONS=TRUE)."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                f"Database {audit_client.database_name} does not audit SYS "
                "administrative operations (AUDIT_SYS_OPERATIONS=FALSE)."
            )
        findings.append(report)
        return findings
