"""Check for VPC endpoints enforcing private connectivity to Amazon Bedrock."""

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class bedrock_access_private_connectivity_enforced(Check):
    """Ensure VPC endpoints enforce private connectivity for Amazon Bedrock.

    This check evaluates whether each VPC has a VPC endpoint for the
    Bedrock Runtime service to enforce private connectivity over AWS PrivateLink.
    - PASS: The VPC has a Bedrock Runtime VPC endpoint configured.
    - FAIL: The VPC does not have a Bedrock Runtime VPC endpoint configured.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for vpc_id, vpc in vpc_client.vpcs.items():
            if vpc_client.provider.scan_unused_services or vpc.in_use:
                report = Check_Report_AWS(metadata=self.metadata(), resource=vpc)
                report.status = "FAIL"
                report.status_extended = f"VPC {vpc.id} does not have a Bedrock Runtime VPC endpoint configured to enforce private connectivity."
                for endpoint in vpc_client.vpc_endpoints:
                    if (
                        endpoint.vpc_id == vpc_id
                        and "bedrock-runtime" in endpoint.service_name
                    ):
                        report.status = "PASS"
                        report.status_extended = f"VPC {vpc.id} has a Bedrock Runtime {endpoint.type} VPC endpoint configured to enforce private connectivity."
                        break

                findings.append(report)

        return findings
