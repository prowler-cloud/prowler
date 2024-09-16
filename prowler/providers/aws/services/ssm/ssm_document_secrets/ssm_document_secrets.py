import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import detect_secrets_scan
from prowler.providers.aws.services.ssm.ssm_client import ssm_client


class ssm_document_secrets(Check):
    def execute(self):
        findings = []
        secrets_ignore_patterns = ssm_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        for document in ssm_client.documents.values():
            report = Check_Report_AWS(self.metadata())
            report.region = document.region
            report.resource_arn = document.arn
            report.resource_id = document.name
            report.resource_tags = document.tags
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in SSM Document {document.name}."
            )

            if document.content:
                detect_secrets_output = detect_secrets_scan(
                    data=json.dumps(document.content, indent=2),
                    excluded_secrets=secrets_ignore_patterns,
                )
                if detect_secrets_output:
                    secrets_string = ", ".join(
                        [
                            f"{secret['type']} on line {secret['line_number']}"
                            for secret in detect_secrets_output
                        ]
                    )
                    report.status = "FAIL"
                    report.status_extended = f"Potential secret found in SSM Document {document.name} -> {secrets_string}."

            findings.append(report)

        return findings
