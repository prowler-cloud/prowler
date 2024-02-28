from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class vpc_different_regions(Check):
    def execute(self):
        findings = []
        if len(vpc_client.vpcs) > 0:
            vpc_regions = set()
            for vpc in vpc_client.vpcs.values():
                if not vpc.default:
                    vpc_regions.add(vpc.region)

            report = Check_Report_AWS(self.metadata())
            report.region = vpc_client.region
            report.resource_id = vpc_client.audited_account
            report.resource_arn = vpc_client.vpc_arn_template

            report.status = "FAIL"
            report.status_extended = "VPCs found only in one region."

            if len(vpc_regions) > 1:
                report.status = "PASS"
                report.status_extended = "VPCs found in more than one region."
            findings.append(report)

        return findings
