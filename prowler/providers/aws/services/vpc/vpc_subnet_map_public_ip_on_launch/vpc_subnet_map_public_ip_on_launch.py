from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class vpc_subnet_map_public_ip_on_launch(Check):
    def execute(self):
        findings = []
        for vpc in vpc_client.vpcs.values():
            for subnet in vpc.subnets:
                report = Check_Report_AWS(self.metadata())
                report.region = subnet.region
                report.resource_tags = subnet.tags
                report.resource_id = subnet.id

                if subnet.mapPublicIpOnLaunch:
                    report.status = "FAIL"
                    report.status_extended = (f"Subnet {subnet.id} has automatic public IP mapping")
                else:
                    report.status = "PASS"
                    report.status_extended = (f"Subnet {subnet.id} does NOT have automatic public IP mapping")
                findings.append(report)

        return findings
