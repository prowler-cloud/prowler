from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class vpc_endpoint_multi_az_enabled(Check):
    def execute(self):
        findings = []
        for endpoint in vpc_client.vpc_endpoints:
            if endpoint.vpc_id in vpc_client.vpcs and endpoint.type == "Interface":
                report = Check_Report_AWS(metadata=self.metadata(), resource=endpoint)
                report.status = "FAIL"
                report.status_extended = f"VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id} does not have subnets in different AZs."
                if len(endpoint.subnet_ids) > 1:
                    report.status = "PASS"
                    report.status_extended = f"VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id} has subnets in different AZs."

                findings.append(report)

        return findings
