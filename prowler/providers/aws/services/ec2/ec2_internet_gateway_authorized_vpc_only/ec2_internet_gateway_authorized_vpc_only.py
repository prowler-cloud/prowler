from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_internet_gateway_authorized_vpc_only(Check):
    def execute(self):
        findings = []
        authorized_vpcs = self.get_authorized_vpcs()  # Get list of authorized VPCs

        for igw in ec2_client.internet_gateways:  # Iterate over internet gateways
            report = Check_Report_AWS(self.metadata())
            report.region = igw.region
            report.resource_id = igw.id
            report.resource_arn = igw.arn

            # Check if the Internet Gateway is attached to unauthorized VPCs
            unauthorized_vpcs = [
                vpc for vpc in igw.attachments if vpc not in authorized_vpcs
            ]
            if unauthorized_vpcs:
                report.status = "FAIL"
                report.status_extended = f"Internet Gateway {igw.id} is attached to unauthorized VPCs: {', '.join(unauthorized_vpcs)}."
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Internet Gateway {igw.id} is attached only to authorized VPCs."
                )

            findings.append(report)

        return findings

    def get_authorized_vpcs(self):
        authorized_vpcs = []
        for vpc in ec2_client.vpcs:  # Iterate over VPCs in the new service
            for tag in vpc.tags:
                if tag["Key"] == "Authorized" and tag["Value"].lower() == "true":
                    authorized_vpcs.append(vpc.id)
        return authorized_vpcs
