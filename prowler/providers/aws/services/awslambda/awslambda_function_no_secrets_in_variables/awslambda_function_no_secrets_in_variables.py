import json
import os
import tempfile

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class awslambda_function_no_secrets_in_variables(Check):
    def execute(self):
        findings = []
        for function in awslambda_client.functions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = function.region
            report.resource_id = function.name
            report.resource_arn = function.arn

            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in Lambda function {function.name} variables"
            )

            if function.environment:
                temp_env_data_file = tempfile.NamedTemporaryFile(delete=False)
                temp_env_data_file.write(
                    bytes(
                        json.dumps(function.environment), encoding="raw_unicode_escape"
                    )
                )
                temp_env_data_file.close()
                secrets = SecretsCollection()
                with default_settings():
                    secrets.scan_file(temp_env_data_file.name)

                if secrets.json():
                    report.status = "FAIL"
                    report.status_extended = f"Potential secret found in Lambda function {function.name} variables"

                os.remove(temp_env_data_file.name)

            findings.append(report)

        return findings
