from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.iam.iam_client import iam_client
from prowler.providers.gcp.services.monitoring.monitoring_client import (
    monitoring_client,
)


class iam_sa_dormant_user_managed_keys(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        keys_used = monitoring_client.sa_keys_metrics
        print("--------- KEYS -------- :", keys_used)
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
                        report.status_extended = f"User-managed key {key.name} for account {account.email} was used over the last 180 days."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"User-managed key {key.name} for account {account.email} was not used over the last 180 days. Consider deleting it."
                    findings.append(report)

        return findings
