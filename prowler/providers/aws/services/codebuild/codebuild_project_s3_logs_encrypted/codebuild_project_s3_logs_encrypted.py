from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client


class codebuild_project_s3_logs_encrypted(Check):
    def execute(self):
        findings = []
        for project in codebuild_client.projects.values():
            if getattr(project, "s3_logs", None):
                report = Check_Report_AWS(self.metadata())
                report.region = project.region
                report.resource_id = project.name
                report.resource_arn = project.arn
                report.status = "PASS"
                report.status_extended = f"CodeBuild project {project.name} has S3 logs stored in {project.s3_logs.bucket_location} are encrypted."

                if not project.s3_logs.encrypted:
                    report.status = "FAIL"
                    report.status_extended = f"CodeBuild project {project.name} has S3 logs stored in {project.s3_logs.bucket_location} are not encrypted."

                findings.append(report)

        return findings
