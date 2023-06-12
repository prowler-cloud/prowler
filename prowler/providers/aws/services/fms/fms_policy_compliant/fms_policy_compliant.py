from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.fms.fms_client import fms_client


class fms_policy_compliant(Check):
    def execute(self):
        findings = []
        if fms_client.fms_admin_account:
            report = Check_Report_AWS(self.metadata())
            report.resource_arn = f"arn:aws:iam::{fms_client.audited_account}:root"
            report.resource_id = fms_client.audited_account
            report.region = fms_client.region
            report.status = "PASS"
            report.status_extended = "FMS enabled with all compliant accounts"
            non_compliant_policy = False
            for policy in fms_client.fms_policies:
                for policy_to_account in policy.compliance_status:
                    if policy_to_account.status == "NON_COMPLIANT":
                        report.status = "FAIL"
                        report.status_extended = f"FMS with non-compliant policy {policy.name} for account {policy_to_account.account_id}"
                        report.resource_id = policy.id
                        report.resource_arn = policy.arn
                        non_compliant_policy = True
                        break
                if non_compliant_policy:
                    break

            findings.append(report)
        return findings
