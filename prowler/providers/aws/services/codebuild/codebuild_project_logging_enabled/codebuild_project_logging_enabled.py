from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client


class codebuild_project_logging_enabled(Check):
    def execute(self):
        findings = []
        for project in codebuild_client.projects.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=project)
            report.status = "PASS"

            cw_logs_enabled = (
                project.cloudwatch_logs and project.cloudwatch_logs.enabled
            )
            s3_logs_enabled = project.s3_logs and project.s3_logs.enabled

            if cw_logs_enabled and s3_logs_enabled:
                report.status_extended = f"CodeBuild project {project.name} has enabled CloudWatch logs in log group {project.cloudwatch_logs.group_name} and S3 logs in bucket {project.s3_logs.bucket_location}."
            elif cw_logs_enabled:
                report.status_extended = f"CodeBuild project {project.name} has CloudWatch logging enabled in log group {project.cloudwatch_logs.group_name}."
            elif s3_logs_enabled:
                report.status_extended = f"CodeBuild project {project.name} has S3 logging enabled in bucket {project.s3_logs.bucket_location}."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"CodeBuild project {project.name} does not have logging enabled."
                )

            findings.append(report)

        return findings
