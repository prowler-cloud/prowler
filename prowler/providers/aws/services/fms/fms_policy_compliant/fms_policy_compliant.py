from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.fms.fms_client import fms_client


class fms_policy_compliant(Check):
    def execute(self):
        findings = []
        if fms_client.fms_admin_account:
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=fms_client.fms_policies
            )
            report.region = fms_client.region
            report.resource_arn = fms_client.policy_arn_template
            report.resource_id = fms_client.audited_account
            report.status = "PASS"
            report.status_extended = "FMS enabled with all compliant accounts."
            non_compliant_policy = False
            if fms_client.fms_policies:
                for policy in fms_client.fms_policies:
                    for policy_to_account in policy.compliance_status:
                        if (
                            policy_to_account.status == "NON_COMPLIANT"
                            or not policy_to_account.status
                        ):
                            report = Check_Report_AWS(
                                metadata=self.metadata(), resource_metadata=policy
                            )
                            report.status = "FAIL"
                            report.status_extended = f"FMS with non-compliant policy {policy.name} for account {policy_to_account.account_id}."
                            report.region = fms_client.region
                            non_compliant_policy = True
                            break
                    if non_compliant_policy:
                        break
            else:
                report.status = "FAIL"
                report.status_extended = f"FMS without any compliant policy for account {fms_client.audited_account}."

            findings.append(report)
        return findings
