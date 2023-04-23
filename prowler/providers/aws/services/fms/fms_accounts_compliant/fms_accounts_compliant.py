from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.fms.fms_client import fms_client


class fms_accounts_compliant(Check):
    def execute(self):
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.resource_id = "FMS"
        report.resource_arn = ""
        report.region = fms_client.region
        report.status = "PASS"
        report.status_extended = "FMS disabled or not admin account"
        if fms_client.fms_admin_account:
            report.status_extended = "FMS enabled with all compliant accounts"
            for policy in fms_client.fms_policies:
                for policy_to_account in policy.compliance_status:
                    if policy_to_account.status == "NON_COMPLIANT":
                        report.status = "FAIL"
                        report.status_extended = f"FMS with non-compliant policy {policy.name} for account {policy_to_account.account_id}"
                        report.resource_id = policy.id
                        report.resource_arn = policy.arn
                        findings.append(report)
                        return findings

        findings.append(report)
        return findings
