from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.iam.iam_client import iam_client


class iam_sa_no_user_managed_keys(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for account in iam_client.service_accounts:
            report = Check_Report_GCP(self.metadata())
            report.project_id = account.project_id
            report.resource_id = account.email
            report.resource_name = account.name
            report.location = iam_client.region
            report.status = "PASS"
            report.status_extended = (
                f"Account {account.email} does not have user-managed keys."
            )
            for key in account.keys:
                if key.type == "USER_MANAGED":
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Account {account.email} has user-managed keys."
                    )
            findings.append(report)

        return findings
