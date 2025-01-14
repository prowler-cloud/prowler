from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudformation.cloudformation_client import (
    cloudformation_client,
)


class cloudformation_stacks_termination_protection_enabled(Check):
    """Check if a CloudFormation Stack has the Termination Protection enabled"""

    def execute(self):
        """Execute the cloudformation_stacks_termination_protection_enabled check"""
        findings = []
        for stack in cloudformation_client.stacks:
            if not stack.is_nested_stack:
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource_metadata=stack
                )

                if stack.enable_termination_protection:
                    report.status = "PASS"
                    report.status_extended = f"CloudFormation Stack {stack.name} has termination protection enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"CloudFormation Stack {stack.name} has termination protection disabled."
                findings.append(report)

        return findings
