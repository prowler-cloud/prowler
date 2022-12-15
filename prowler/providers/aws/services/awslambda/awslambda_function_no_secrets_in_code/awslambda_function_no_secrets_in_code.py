import os
import tempfile

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class awslambda_function_no_secrets_in_code(Check):
    def execute(self):
        findings = []
        for function in awslambda_client.functions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = function.region
            report.resource_id = function.name
            report.resource_arn = function.arn

            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in Lambda function {function.name} code"
            )

            with tempfile.TemporaryDirectory() as tmp_dir_name:
                function.code.code_zip.extractall(tmp_dir_name)
                # List all files
                files_in_zip = next(os.walk(tmp_dir_name))[2]
                for file in files_in_zip:

                    secrets = SecretsCollection()
                    with default_settings():
                        secrets.scan_file(f"{tmp_dir_name}/{file}")

                    if secrets.json():
                        report.status = "FAIL"
                        report.status_extended = f"Potential secret found in Lambda function {function.name} code"
                        break

            findings.append(report)

        return findings
