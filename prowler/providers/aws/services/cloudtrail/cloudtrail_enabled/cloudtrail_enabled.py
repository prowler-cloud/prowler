from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import cloudtrail_client


class cloudtrail_enabled(Check):
    def execute(self):
        findings = []

        for trail_arn, trail in cloudtrail_client.trails.items():
            report = Check_Report_AWS(self.metadata())
            report.region = trail.region
            report.resource_arn = trail.arn if trail.arn else "Unknown"
            report.resource_id = trail.name if trail.name else "Unknown"
            report.resource_tags = trail.tags if trail.tags else []

            if trail.is_logging:
                report.status = "PASS"
                report.status_extended = f"CloudTrail {trail.name if trail.name else 'Unknown'} is enabled and logging in {trail.region}."
            else:
                report.status = "FAIL"
                report.status_extended = f"CloudTrail {trail.name if trail.name else 'Unknown'} is not enabled or not logging in {trail.region}."

            findings.append(report)

        return findings
