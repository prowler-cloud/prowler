from ipaddress import ip_address

import awsipranges

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import validate_ip_address
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.route53.route53_client import route53_client


class route53_dangling_ip_subdomain_takeover(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        for record_set in route53_client.record_sets:
            # Check only A records and avoid aliases (only need to check IPs not AWS Resources)
            if record_set.type == "A" and not record_set.is_alias:
                # Gather Elastic IPs and Network Interfaces Public IPs inside the AWS Account
                public_ips = []
                public_ips.extend([eip.public_ip for eip in ec2_client.elastic_ips])
                # Add public IPs from Network Interfaces
                for network_interface in ec2_client.network_interfaces.values():
                    if (
                        network_interface.association
                        and network_interface.association.get("PublicIp")
                    ):
                        public_ips.append(network_interface.association.get("PublicIp"))
                for record in record_set.records:
                    # Check if record is an IP Address
                    if validate_ip_address(record):
                        report = Check_Report_AWS(self.metadata())
                        report.resource_id = (
                            f"{record_set.hosted_zone_id}/{record_set.name}/{record}"
                        )
                        report.resource_arn = route53_client.hosted_zones[
                            record_set.hosted_zone_id
                        ].arn
                        report.resource_tags = route53_client.hosted_zones[
                            record_set.hosted_zone_id
                        ].tags
                        report.region = record_set.region
                        report.status = "PASS"
                        report.status_extended = f"Route53 record {record} (name: {record_set.name}) in Hosted Zone {route53_client.hosted_zones[record_set.hosted_zone_id].name} is not a dangling IP."
                        # If Public IP check if it is in the AWS Account
                        if (
                            not ip_address(record).is_private
                            and record not in public_ips
                        ):
                            report.status_extended = f"Route53 record {record} (name: {record_set.name}) in Hosted Zone {route53_client.hosted_zones[record_set.hosted_zone_id].name} does not belong to AWS and it is not a dangling IP."
                            # Check if potential dangling IP is within AWS Ranges
                            aws_ip_ranges = awsipranges.get_ranges()
                            if aws_ip_ranges.get(record):
                                report.status = "FAIL"
                                report.status_extended = f"Route53 record {record} (name: {record_set.name}) in Hosted Zone {route53_client.hosted_zones[record_set.hosted_zone_id].name} is a dangling IP which can lead to a subdomain takeover attack."
                        findings.append(report)

        return findings
