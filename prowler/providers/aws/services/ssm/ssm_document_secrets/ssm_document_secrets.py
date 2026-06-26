import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.ssm.ssm_client import ssm_client


class ssm_document_secrets(Check):
    def execute(self):
        findings = []
        secrets_ignore_patterns = ssm_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = ssm_client.audit_config.get("secrets_validate", False)
        documents = list(ssm_client.documents.values())

        # Collect one payload per document (its content) and scan them all in
        # batched Kingfisher invocations instead of one subprocess per document.
        def payloads():
            for index, document in enumerate(documents):
                if document.content:
                    yield index, json.dumps(document.content, indent=2)

        batch_results = detect_secrets_scan_batch(
            payloads(), excluded_secrets=secrets_ignore_patterns, validate=validate
        )

        for index, document in enumerate(documents):
            report = Check_Report_AWS(metadata=self.metadata(), resource=document)
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in SSM Document {document.name}."
            )

            if document.content:
                detect_secrets_output = batch_results.get(index)
                if detect_secrets_output:
                    secrets_string = ", ".join(
                        [
                            f"{secret['type']} on line {secret['line_number']}"
                            for secret in detect_secrets_output
                        ]
                    )
                    report.status = "FAIL"
                    report.status_extended = f"Potential secret found in SSM Document {document.name} -> {secrets_string}."
                    annotate_verified_secrets(report, detect_secrets_output)

            findings.append(report)

        return findings
