from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_ami_account_block_public_access(Check):
    def execute(self):
        findings = []
        for state in ec2_client.ami_block_public_access_states:
            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource=state,
            )
            report.resource_id = ec2_client.audited_account
            report.resource_arn = ec2_client.account_arn_template

            if state.status == "block-new-sharing":
                report.status = "PASS"
                report.status_extended = (
                    f"AMI Block Public Access is enabled in {state.region}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"AMI Block Public Access is disabled in {state.region}."
                )

            findings.append(report)

        return findings
