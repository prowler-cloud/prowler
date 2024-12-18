from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client


class codebuild_project_logging_enabled(Check):
    def execute(self):
        findings = []
        for project in codebuild_client.projects.values():
            report = Check_Report_AWS(self.metadata())
            report.resource_id = project.name
            report.resource_arn = project.arn
            report.region = project.region
            report.resource_tags = project.tags
            report.status = "PASS"

            if getattr(
                getattr(project, "cloudwatch_logs", None), "enabled", False
            ) and getattr(getattr(project, "s3_logs", None), "enabled", False):
                report.status_extended = f"CodeBuild project {project.name} has enabled CloudWartch logs in log group {project.cloudwatch_logs.group_name} and S3 logs in bucket {project.s3_logs.bucket_location}."
            elif getattr(getattr(project, "cloudwatch_logs", None), "enabled", False):
                report.status_extended = f"CodeBuild project {project.name} has CloudWatch logging enabled in log group {project.cloudwatch_logs.group_name}."
            elif getattr(getattr(project, "s3_logs", None), "enabled", False):
                report.status_extended = f"CodeBuild project {project.name} has S3 logging enabled in bucket {project.s3_logs.bucket_location}."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"CodeBuild project {project.name} does not have logging enabled."
                )

            findings.append(report)

        return findings
