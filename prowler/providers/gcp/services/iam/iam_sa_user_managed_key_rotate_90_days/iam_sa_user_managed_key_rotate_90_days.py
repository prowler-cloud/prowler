from datetime import datetime

from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.iam.iam_client import iam_client


class iam_sa_user_managed_key_rotate_90_days(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for account in iam_client.service_accounts:
            for key in account.keys:
                if key.type == "USER_MANAGED":
                    last_rotated = (datetime.now() - key.valid_after).days
                    report = Check_Report_GCP(self.metadata())
                    report.project_id = account.project_id
                    report.resource_id = key.name
                    report.resource_name = account.email
                    report.location = iam_client.region
                    report.status = "PASS"
                    report.status_extended = f"User-managed key {key.name} for account {account.email} was rotated over the last 90 days ({last_rotated} days ago)"
                    if last_rotated > 90:
                        report.status = "FAIL"
                        report.status_extended = f"User-managed key {key.name} for account {account.email} was not rotated over the last 90 days ({last_rotated} days ago)"
                    findings.append(report)

        return findings
