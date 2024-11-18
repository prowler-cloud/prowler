from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client


class codebuild_project_s3_logs_encrypted(Check):
    def execute(self):
        findings = []
        for project in codebuild_client.projects.values():
            if project.s3_logs.enabled:
                report = Check_Report_AWS(self.metadata())
                report.resource_id = project.name
                report.resource_arn = project.arn
                report.region = project.region
                report.resource_tags = project.tags
                report.status = "PASS"
                report.status_extended = f"CodeBuild project {project.name} has encrypted S3 logs stored in {project.s3_logs.bucket_location}."
                if not project.s3_logs.encrypted:
                    report.status = "FAIL"
                    report.status_extended = f"CodeBuild project {project.name} does not have encrypted S3 logs stored in {project.s3_logs.bucket_location}."

                findings.append(report)

        return findings
