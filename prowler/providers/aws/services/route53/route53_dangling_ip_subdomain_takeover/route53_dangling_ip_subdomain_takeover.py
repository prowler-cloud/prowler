import re
from ipaddress import ip_address

import awsipranges

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import validate_ip_address
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.route53.route53_client import route53_client
from prowler.providers.aws.services.s3.s3_client import s3_client

# S3 website endpoint formats:
#   <bucket>.s3-website-<region>.amazonaws.com   (legacy, dash)
#   <bucket>.s3-website.<region>.amazonaws.com   (newer, dot)
S3_WEBSITE_ENDPOINT_REGEX = re.compile(
    r"^(?P<bucket>[^.]+(?:\.[^.]+)*)\.s3-website[.-](?P<region>[a-z0-9-]+)\.amazonaws\.com\.?$"
)


class route53_dangling_ip_subdomain_takeover(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        # When --region is used, Route53 service gathers EIPs from all regions
        # to avoid false positives. Otherwise, use ec2_client data directly.
        if route53_client.all_account_elastic_ips:
            public_ips = list(route53_client.all_account_elastic_ips)
        else:
            public_ips = [eip.public_ip for eip in ec2_client.elastic_ips]

        # Add Network Interface public IPs from audited regions
        for ni in ec2_client.network_interfaces.values():
            if ni.association and ni.association.get("PublicIp"):
                public_ips.append(ni.association.get("PublicIp"))

        owned_bucket_names = {bucket.name for bucket in s3_client.buckets.values()}

        for record_set in route53_client.record_sets:
            hosted_zone = route53_client.hosted_zones[record_set.hosted_zone_id]

            # A records: dangling-IP path (released EIPs / unowned AWS IPs)
            if record_set.type == "A" and not record_set.is_alias:
                for record in record_set.records:
                    if validate_ip_address(record):
                        report = Check_Report_AWS(
                            metadata=self.metadata(), resource=record_set
                        )
                        report.resource_id = (
                            f"{record_set.hosted_zone_id}/{record_set.name}/{record}"
                        )
                        report.resource_arn = hosted_zone.arn
                        report.resource_tags = hosted_zone.tags
                        report.status = "PASS"
                        report.status_extended = f"Route53 record {record} (name: {record_set.name}) in Hosted Zone {hosted_zone.name} is not a dangling IP."
                        # If Public IP check if it is in the AWS Account
                        if (
                            not ip_address(record).is_private
                            and record not in public_ips
                        ):
                            report.status_extended = f"Route53 record {record} (name: {record_set.name}) in Hosted Zone {hosted_zone.name} does not belong to AWS and it is not a dangling IP."
                            # Check if potential dangling IP is within AWS Ranges
                            aws_ip_ranges = awsipranges.get_ranges()
                            if aws_ip_ranges.get(record):
                                report.status = "FAIL"
                                report.status_extended = f"Route53 record {record} (name: {record_set.name}) in Hosted Zone {hosted_zone.name} is a dangling IP which can lead to a subdomain takeover attack."
                        findings.append(report)

            # CNAME records: dangling S3 website endpoint
            # (deleted bucket whose name can be re-registered by anyone)
            elif record_set.type == "CNAME" and not record_set.is_alias:
                for record in record_set.records:
                    match = S3_WEBSITE_ENDPOINT_REGEX.match(record.lower())
                    if not match:
                        continue
                    bucket_name = match.group("bucket")
                    report = Check_Report_AWS(
                        metadata=self.metadata(), resource=record_set
                    )
                    report.resource_id = (
                        f"{record_set.hosted_zone_id}/{record_set.name}/{record}"
                    )
                    report.resource_arn = hosted_zone.arn
                    report.resource_tags = hosted_zone.tags
                    if bucket_name in owned_bucket_names:
                        report.status = "PASS"
                        report.status_extended = f"Route53 CNAME {record_set.name} in Hosted Zone {hosted_zone.name} points to S3 website endpoint of bucket {bucket_name} which exists in the account."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"Route53 CNAME {record_set.name} in Hosted Zone {hosted_zone.name} points to S3 website endpoint of bucket {bucket_name} which does not exist in the account and can lead to a subdomain takeover attack."
                    findings.append(report)

        return findings
