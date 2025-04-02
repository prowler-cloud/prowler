from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.iam.iam_client import iam_client
from prowler.providers.gcp.services.monitoring.monitoring_client import (
    monitoring_client,
)


class iam_sa_no_user_managed_keys(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        sys_managed_keys = 0
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
                    report.status = "FAIL"
                    if key.name in keys_used:
                        report.status_extended = (
                            f"Account {account.email} has user-managed keys."
                        )
                    else:
                        report.status_extended = f"Account {account.email} has user-managed keys. The user-managed key {key.name} was not used over the last 180 days."
                    findings.append(report)

                else:
                    sys_managed_keys += 1

            if len(account.keys) == 0:
                report = Check_Report_GCP(
                    metadata=self.metadata(),
                    resource=account,
                    resource_id=account.email,
                    location=iam_client.region,
                )
                report.status = "PASS"
                report.status_extended = (
                    f"Account {account.email} does not have user-managed keys."
                )
                findings.append(report)

            if len(account.keys) > 0 and len(account.keys) == sys_managed_keys:
                report = Check_Report_GCP(
                    metadata=self.metadata(),
                    resource=account,
                    resource_id=account.email,
                    location=iam_client.region,
                )
                report.status = "PASS"
                report.status_extended = (
                    f"Account {account.email} does not have user-managed keys."
                )
                findings.append(report)

        return findings
