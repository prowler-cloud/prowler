"""Check Ensure audit log retention period is set to 365 days or greater."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.audit.audit_client import audit_client


class audit_log_retention_period_365_days(Check):
    """Check Ensure audit log retention period is set to 365 days or greater."""

    def execute(self) -> Check_Report_OCI:
        """Execute the audit_log_retention_period_365_days check."""
        findings = []

        # Check audit log retention period
        if audit_client.configuration:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=audit_client.configuration,
                region="global",
                resource_name="Audit Configuration",
                resource_id=audit_client.audited_tenancy,
                compartment_id=audit_client.audited_tenancy,
            )

            if audit_client.configuration.retention_period_days >= 365:
                report.status = "PASS"
                report.status_extended = f"Audit log retention period is {audit_client.configuration.retention_period_days} days (365 days or greater)."
            else:
                report.status = "FAIL"
                report.status_extended = f"Audit log retention period is {audit_client.configuration.retention_period_days} days (less than 365 days)."

            findings.append(report)
        else:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource={},
                region="global",
                resource_name="Audit Configuration",
                resource_id=audit_client.audited_tenancy,
                compartment_id=audit_client.audited_tenancy,
            )
            report.status = "FAIL"
            report.status_extended = "Audit configuration not found."
            findings.append(report)

        return findings
