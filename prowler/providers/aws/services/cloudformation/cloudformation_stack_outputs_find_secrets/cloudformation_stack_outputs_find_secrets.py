from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import detect_secrets_scan
from prowler.providers.aws.services.cloudformation.cloudformation_client import (
    cloudformation_client,
)


class cloudformation_stack_outputs_find_secrets(Check):
    """Check if a CloudFormation Stack has secrets in their Outputs"""

    def execute(self):
        """Execute the cloudformation_stack_outputs_find_secrets check"""
        findings = []
        secrets_ignore_patterns = cloudformation_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        for stack in cloudformation_client.stacks:
            report = Check_Report_AWS(self.metadata())
            report.region = stack.region
            report.resource_id = stack.name
            report.resource_arn = stack.arn
            report.resource_tags = stack.tags
            report.status = "PASS"
            report.status_extended = f"No secrets found in Stack {stack.name} Outputs."
            if stack.outputs:
                data = ""
                # Store the CloudFormation Stack Outputs into a file
                for output in stack.outputs:
                    data += f"{output}\n"

                detect_secrets_output = detect_secrets_scan(
                    data=data, excluded_secrets=secrets_ignore_patterns
                )
                # If secrets are found, update the report status
                if detect_secrets_output:
                    secrets_string = ", ".join(
                        [
                            f"{secret['type']} in Output {int(secret['line_number'])}"
                            for secret in detect_secrets_output
                        ]
                    )
                    report.status = "FAIL"
                    report.status_extended = f"Potential secret found in Stack {stack.name} Outputs -> {secrets_string}."

            else:
                report.status = "PASS"
                report.status_extended = f"CloudFormation {stack.name} has no Outputs."

            findings.append(report)

        return findings
