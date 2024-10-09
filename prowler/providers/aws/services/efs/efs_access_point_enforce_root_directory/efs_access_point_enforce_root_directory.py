from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.efs.efs_client import efs_client


class efs_access_point_enforce_root_directory(Check):
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
                report.status_extended = f"EFS {fs.id} does not have any access point allowing access to the root directory."
                access_points = []
                for access_point in fs.access_points:
                    if access_point.root_directory_path == "/":
                        access_points.append(access_point)
                if access_points:
                    report.status = "FAIL"
                    report.status_extended = f"EFS {fs.id} has access points which allow access to the root directory: {', '.join([ap.id for ap in access_points])}."
                findings.append(report)
        return findings
