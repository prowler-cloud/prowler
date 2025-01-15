from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_transitgateway_auto_accept_vpc_attachments(Check):
    def execute(self):
        findings = []
        for tgw in ec2_client.transit_gateways.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource_metadata=tgw)

            if tgw.auto_accept_shared_attachments:
                report.status = "FAIL"
                report.status_extended = f"Transit Gateway {tgw.id} in region {tgw.region} is configured to automatically accept shared VPC attachments."
            else:
                report.status = "PASS"
                report.status_extended = f"Transit Gateway {tgw.id} in region {tgw.region} does not automatically accept shared VPC attachments."

            findings.append(report)

        return findings
