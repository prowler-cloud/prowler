from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class vpc_different_regions(Check):
    def execute(self):
        findings = []
        region = None
        for vpc in vpc_client.vpcs:
            if not vpc.default:
                report = Check_Report_AWS(self.metadata())
                # This is a global check under the vpc service: region, resource_id and tags are not relevant here but we keep them for consistency
                report.region = vpc.region
                report.resource_id = vpc.id
                report.resource_tags = vpc.tags
                report.status = "FAIL"
                report.status_extended = f"VPCs found only in one region {vpc.region}."
                if region and vpc.region != region:
                    report.status = "PASS"
                    report.status_extended = "VPCs found in more than one region."
                    break
                region = vpc.region

        findings.append(report)

        return findings
