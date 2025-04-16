from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.iam.iam_client import iam_client
from prowler.providers.gcp.services.monitoring.monitoring_client import (
    monitoring_client,
)


class iam_sa_user_managed_key_unused(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        max_unused_days = monitoring_client.audit_config.get(
            "max_unused_account_days", 180
        )
        keys_used = monitoring_client.sa_keys_metrics
        for account in iam_client.service_accounts:
            for key in account.keys:
                if key.type == "USER_MANAGED":
                    report = Check_Report_GCP(
                        metadata=self.metadata(),
                        resource=account,
                        resource_id=key.name,
                        resource_name=account.email,
                        location=iam_client.region,
                    )
                    if key.name in keys_used:
                        report.status = "PASS"
                        report.status_extended = f"User-managed key {key.name} for Service Account {account.email} was used over the last {max_unused_days} days."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"User-managed key {key.name} for Service Account {account.email} was not used over the last {max_unused_days} days."
                    findings.append(report)

        return findings
