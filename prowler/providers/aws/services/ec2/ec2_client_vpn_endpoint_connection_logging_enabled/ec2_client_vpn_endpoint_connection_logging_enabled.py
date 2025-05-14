from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_client_vpn_endpoint_connection_logging_enabled(Check):
    def execute(self):
        findings = []
        for vpn_arn, vpn_endpoint in ec2_client.vpn_endpoints.items():
            report = Check_Report_AWS(metadata=self.metadata(), resource=vpn_endpoint)

            if vpn_endpoint.connection_logging:
                report.status = "PASS"
                report.status_extended = f"Client VPN endpoint {vpn_endpoint.id} in region {vpn_endpoint.region} has client connection logging enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"Client VPN endpoint {vpn_endpoint.id} in region {vpn_endpoint.region} does not have client connection logging enabled."

            findings.append(report)

        return findings
