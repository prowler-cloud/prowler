from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client


class codebuild_project_no_plaintext_credentials(Check):
    def execute(self):
        findings = []
        for project in codebuild_client.projects.values():
            report = Check_Report_AWS(self.metadata())
            report.region = project.region
            report.resource_id = project.name
            report.resource_arn = project.arn
            report.status = "PASS"
            report.status_extended = f"CodeBuild project {project.name} does not have environment plaintext credentials."
            sensitive_vars = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
            for var in project.environment_variables:
                if var.name in sensitive_vars and var.type == "PLAINTEXT":
                    report.status = "FAIL"
                    report.status_extended = f"CodeBuild project {project.name} has environment plaintext credentials."
                    break
            findings.append(report)

        return findings
