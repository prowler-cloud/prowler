from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.efs.efs_client import efs_client


class efs_access_point_enforce_user_identity(Check):
    def execute(self):
        findings = []
        for fs in efs_client.filesystems.values():
            if fs.access_points:
                report = Check_Report_AWS(self.metadata())
                report.region = fs.region
                report.resource_id = fs.id
                report.resource_arn = fs.arn
                report.resource_tags = fs.tags
                report.status = "PASS"
                report.status_extended = (
                    f"EFS {fs.id} has all access points with defined POSIX user."
                )

                access_points = []
                for access_point in fs.access_points:
                    if not access_point.posix_user:
                        access_points.append(access_point)
                if access_points:
                    report.status = "FAIL"
                    report.status_extended = f"EFS {fs.id} has access points with no POSIX user: {', '.join([ap.id for ap in access_points])}."
                findings.append(report)
        return findings
