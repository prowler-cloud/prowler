from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class vpc_endpoint_multi_az(Check):
    def execute(self):
        findings = []
        for vpc_id, vpc in vpc_client.vpcs.items():
            for endpoint in vpc_client.vpc_endpoints:
                if endpoint.vpc_id == vpc_id and endpoint.type == "Interface":
                    report = Check_Report_AWS(self.metadata())
                    report.region = endpoint.region
                    report.resource_tags = endpoint.tags
                    report.resource_id = endpoint.id
                    report.resource_arn = endpoint.arn
                    report.status = "FAIL"
                    report.status_extended = f"VPC {vpc.id} has {endpoint.service_name} endpoint is not configured for high availibility."
                    if len(endpoint.subnet_id) > 1:
                        report.status = "PASS"
                        report.status_extended = f"VPC {vpc.id} has {endpoint.service_name} endpoint is configured for high availibility."

                    findings.append(report)

        return findings
