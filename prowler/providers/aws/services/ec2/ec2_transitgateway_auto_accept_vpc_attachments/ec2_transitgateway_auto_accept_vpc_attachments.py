from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_transitgateway_auto_accept_vpc_attachments(Check):
    def execute(self):
        findings = []
        for tgw_arn, tgw in ec2_client.transit_gateways.items():
            report = Check_Report_AWS(self.metadata())
            report.region = tgw.region
            report.resource_id = tgw.id
            report.resource_arn = tgw_arn
            report.resource_tags = tgw.tags

            if tgw.auto_accept_shared_attachments:
                report.status = "FAIL"
                report.status_extended = f"Transit Gateway {tgw.id} in region {tgw.region} is configured to automatically accept shared VPC attachments."
            else:
                report.status = "PASS"
                report.status_extended = f"Transit Gateway {tgw.id} in region {tgw.region} does not automatically accept shared VPC attachments."

            findings.append(report)

        return findings
