from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)


class cloudtrail_kms_encryption_enabled(Check):
    def execute(self):
        findings = []
        if cloudtrail_client.trails is not None:
            for trail in cloudtrail_client.trails.values():
                if trail.name:
                    report = Check_Report_AWS(self.metadata())
                    report.region = trail.home_region
                    report.resource_id = trail.name
                    report.resource_arn = trail.arn
                    report.resource_tags = trail.tags
                    report.status = "FAIL"
                    if trail.is_multiregion:
                        report.status_extended = (
                            f"Multiregion trail {trail.name} has encryption disabled."
                        )
                    else:
                        report.status_extended = (
                            f"Single region trail {trail.name} has encryption disabled."
                        )
                    if trail.kms_key:
                        report.status = "PASS"
                        if trail.is_multiregion:
                            report.status_extended = f"Multiregion trail {trail.name} has encryption enabled."
                        else:
                            report.status_extended = f"Single region trail {trail.name} has encryption enabled."
                    findings.append(report)

        return findings
