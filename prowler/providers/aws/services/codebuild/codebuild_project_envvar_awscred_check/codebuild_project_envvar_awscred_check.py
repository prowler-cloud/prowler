from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client


class codebuild_project_envvar_awscred_check(Check):
    def execute(self):
        findings = []

        for project in codebuild_client.projects.values():
            report = Check_Report_AWS(self.metadata())
            report.region = project.region
            report.resource_id = project.name
            report.resource_arn = project.arn
            report.resource_tags = project.tags

            aws_cred_found = False
            for env_var in project.environment_variables:
                if env_var.name in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]:
                    aws_cred_found = True
                    break

            if aws_cred_found:
                report.status = "FAIL"
                report.status_extended = f"CodeBuild project {project.name} has AWS credentials in environment variables."
            else:
                report.status = "PASS"
                report.status_extended = f"CodeBuild project {project.name} does not have AWS credentials in environment variables."

            findings.append(report)

        return findings
