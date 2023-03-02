import json
import os
import tempfile

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ssm.ssm_client import ssm_client


class ssm_document_secrets(Check):
    def execute(self):
        findings = []
        for document in ssm_client.documents.values():
            report = Check_Report_AWS(self.metadata())
            report.region = document.region
            report.resource_arn = document.arn
            report.resource_id = document.name
            report.resource_tags = document.tags
            report.status = "PASS"
            report.status_extended = f"No secrets found in SSM Document {document.name}"

            if document.content:
                temp_env_data_file = tempfile.NamedTemporaryFile(delete=False)
                temp_env_data_file.write(
                    bytes(
                        json.dumps(document.content, indent=2),
                        encoding="raw_unicode_escape",
                    )
                )
                temp_env_data_file.close()
                secrets = SecretsCollection()
                with default_settings():
                    secrets.scan_file(temp_env_data_file.name)

                detect_secrets_output = secrets.json()
                if detect_secrets_output:
                    secrets_string = ", ".join(
                        [
                            f"{secret['type']} on line {secret['line_number']}"
                            for secret in detect_secrets_output[temp_env_data_file.name]
                        ]
                    )
                    report.status = "FAIL"
                    report.status_extended = f"Potential secret found in SSM Document {document.name} -> {secrets_string}"

                os.remove(temp_env_data_file.name)

            findings.append(report)

        return findings
