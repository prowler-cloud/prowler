from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudformation.cloudformation_client import (
    cloudformation_client,
)


class cloudformation_stack_cdktoolkit_bootstrap_version(Check):
    """Check if a CDKToolkit CloudFormation Stack has a Bootstrap version less than recommended"""

    def execute(self):
        """Execute the cloudformation_stack_cdktoolkit_bootstrap_version check"""
        findings = []
        recommended_cdk_bootstrap_version = cloudformation_client.audit_config.get(
            "recommended_cdk_bootstrap_version", 21
        )
        for stack in cloudformation_client.stacks:
            # Only check stacks named CDKToolkit
            if stack.name == "CDKToolkit":
                bootstrap_version = None
                if stack.outputs:
                    for output in stack.outputs:
                        if output.startswith("BootstrapVersion:"):
                            bootstrap_version = int(output.split(":")[1])
                            break
                if bootstrap_version:
                    report = Check_Report_AWS(metadata=self.metadata(), resource=stack)
                    report.status = "PASS"
                    report.status_extended = f"CloudFormation Stack CDKToolkit has a Bootstrap version {bootstrap_version}, which meets the recommended version."
                    if bootstrap_version < recommended_cdk_bootstrap_version:
                        report.status = "FAIL"
                        report.status_extended = f"CloudFormation Stack CDKToolkit has a Bootstrap version {bootstrap_version}, which is less than the recommended version {recommended_cdk_bootstrap_version}."

                    findings.append(report)

        return findings
