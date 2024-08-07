from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client
from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings
import tempfile
import json
import os

class codebuild_project_no_secrets_in_variables(Check):
    def execute(self):
        findings = []
        for project in codebuild_client.projects.values():
            report = Check_Report_AWS(self.metadata())
            report.region = project.region
            report.resource_id = project.name
            report.resource_arn = project.arn
            report.status = "PASS"
            report.status_extended = f"CodeBuild project {project.name} does not have sensitive environment plaintext credentials."
            secrets_found = []

            if project.environment_variables:
                for env_var in project.environment_variables:
                    if env_var.type == "PLAINTEXT":
                        temp_file = tempfile.NamedTemporaryFile(delete=False)
                        temp_file.write(bytes(json.dumps({env_var.name: env_var.value}), encoding='utf-8'))
                        temp_file.close()

                        secrets = SecretsCollection()
                        with default_settings():
                            secrets.scan_file(temp_file.name)

                        if secrets.json():
                            secrets_found.append(env_var.name)
                        
                        os.remove(temp_file.name)

            if secrets_found:
                report.status = "FAIL"
                report.status_extended = f"CodeBuild project {project.name} has sensitive environment plaintext credentials."

            findings.append(report)

        return findings
