from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class bedrock_vpc_endpoints_configured(Check):
    """Ensure VPC endpoints are configured for Bedrock runtime and agent services.

    This check verifies that each VPC has interface VPC endpoints for both
    Amazon Bedrock runtime and Bedrock agent runtime services, ensuring that
    traffic to these services remains within the AWS network.
    - PASS: The VPC has VPC endpoints for both Bedrock runtime and Bedrock agent runtime.
    - FAIL: The VPC is missing one or both Bedrock VPC endpoints.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for vpc_id, vpc in vpc_client.vpcs.items():
            if vpc_client.provider.scan_unused_services or vpc.in_use:
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource=vpc
                )
                report.status = "FAIL"

                has_bedrock_runtime = False
                has_bedrock_agent_runtime = False

                for endpoint in vpc_client.vpc_endpoints:
                    if endpoint.vpc_id == vpc_id:
                        if "bedrock-runtime" in endpoint.service_name:
                            has_bedrock_runtime = True
                        if "bedrock-agent-runtime" in endpoint.service_name:
                            has_bedrock_agent_runtime = True

                if has_bedrock_runtime and has_bedrock_agent_runtime:
                    report.status = "PASS"
                    report.status_extended = f"VPC {vpc.id} has VPC endpoints for both Bedrock runtime and Bedrock agent runtime services."
                else:
                    missing = []
                    if not has_bedrock_runtime:
                        missing.append("Bedrock runtime")
                    if not has_bedrock_agent_runtime:
                        missing.append("Bedrock agent runtime")
                    report.status_extended = f"VPC {vpc.id} does not have VPC endpoints for the following Bedrock services: {', '.join(missing)}."

                findings.append(report)

        return findings
