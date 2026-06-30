from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
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
        validate = cloudformation_client.audit_config.get("secrets_validate", False)
        stacks = list(cloudformation_client.stacks)

        # Collect one payload per stack (its Outputs) and scan them all in
        # batched Kingfisher invocations instead of one subprocess per stack.
        def payloads():
            for index, stack in enumerate(stacks):
                if stack.outputs:
                    yield index, "".join(f"{output}\n" for output in stack.outputs)

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                payloads(), excluded_secrets=secrets_ignore_patterns, validate=validate
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        for index, stack in enumerate(stacks):
            report = Check_Report_AWS(metadata=self.metadata(), resource=stack)
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in CloudFormation Stack {stack.name} Outputs."
            )
            if stack.outputs:
                if scan_error:
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Could not scan CloudFormation Stack {stack.name} Outputs "
                        f"for secrets: {scan_error}; manual review is required."
                    )
                    findings.append(report)
                    continue
                detect_secrets_output = batch_results.get(index)
                if detect_secrets_output:
                    secrets_string = ", ".join(
                        [
                            f"{secret['type']} in Output {int(secret['line_number'])}"
                            for secret in detect_secrets_output
                        ]
                    )
                    report.status = "FAIL"
                    report.status_extended = f"Potential secret found in CloudFormation Stack {stack.name} Outputs -> {secrets_string}."
                    annotate_verified_secrets(report, detect_secrets_output)
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"CloudFormation Stack {stack.name} has no Outputs."
                )

            findings.append(report)

        return findings
