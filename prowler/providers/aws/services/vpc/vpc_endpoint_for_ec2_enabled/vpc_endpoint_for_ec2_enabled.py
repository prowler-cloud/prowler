from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class vpc_endpoint_for_ec2_enabled(Check):
    def execute(self):
        findings = []
        for vpc_id, vpc in vpc_client.vpcs.items():
            if vpc_client.provider.scan_unused_services or vpc.in_use:
                report = Check_Report_AWS(self.metadata())
                report.region = vpc.region
                report.resource_tags = vpc.tags
                report.status = "FAIL"
                report.status_extended = f"VPC {vpc.id} has no EC2 endpoint."
                report.resource_id = vpc.id
                report.resource_arn = vpc.arn
                for endpoint in vpc_client.vpc_endpoints:
                    if endpoint.vpc_id == vpc_id and "ec2" in endpoint.service_name:
                        report.status = "PASS"
                        report.status_extended = (
                            f"VPC {vpc.id} has an EC2 {endpoint.type} endpoint."
                        )
                        break

                findings.append(report)

        return findings
