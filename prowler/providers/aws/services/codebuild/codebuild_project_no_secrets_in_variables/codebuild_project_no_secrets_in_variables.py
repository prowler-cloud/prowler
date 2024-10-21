import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import detect_secrets_scan
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client


class codebuild_project_no_secrets_in_variables(Check):
    def execute(self):
        findings = []
        sensitive_vars_excluded = codebuild_client.audit_config.get(
            "excluded_sensitive_environment_variables", []
        )
        secrets_ignore_patterns = codebuild_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        for project in codebuild_client.projects.values():
            report = Check_Report_AWS(self.metadata())
            report.region = project.region
            report.resource_id = project.name
            report.resource_arn = project.arn
            report.resource_tags = project.tags
            report.status = "PASS"
            report.status_extended = f"CodeBuild project {project.name} does not have sensitive environment plaintext credentials."
            secrets_found = []

            if project.environment_variables:
                for env_var in project.environment_variables:
                    if (
                        env_var.type == "PLAINTEXT"
                        and env_var.name not in sensitive_vars_excluded
                    ):
                        detect_secrets_output = detect_secrets_scan(
                            data=json.dumps({env_var.name: env_var.value}),
                            excluded_secrets=secrets_ignore_patterns,
                        )
                        if detect_secrets_output:
                            secrets_info = [
                                f"{secret['type']} in variable {env_var.name}"
                                for secret in detect_secrets_output
                            ]
                            secrets_found.extend(secrets_info)

            if secrets_found:
                report.status = "FAIL"
                report.status_extended = f"CodeBuild project {project.name} has sensitive environment plaintext credentials in variables: {', '.join(secrets_found)}."

            findings.append(report)

        return findings
