from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.iam.iam_client import iam_client
from prowler.providers.gcp.services.monitoring.monitoring_client import (
    monitoring_client,
)


class iam_service_account_unused(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        max_unused_days = monitoring_client.audit_config.get(
            "max_unused_account_days", 180
        )
        sa_ids_used = monitoring_client.sa_api_metrics
        for account in iam_client.service_accounts:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=account,
                resource_id=account.email,
                location=iam_client.region,
            )
            if account.uniqueId in sa_ids_used:
                report.status = "PASS"
                report.status_extended = f"Service Account {account.email} was used over the last {max_unused_days} days."
            else:
                report.status = "FAIL"
                report.status_extended = f"Service Account {account.email} was not used over the last {max_unused_days} days."
            findings.append(report)

        return findings
