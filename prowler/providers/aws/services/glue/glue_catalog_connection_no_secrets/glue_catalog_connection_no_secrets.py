import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.glue.glue_client import glue_client


class glue_catalog_connection_no_secrets(Check):
    """Check if Glue Data Catalog connections store secrets in ConnectionProperties."""

    def execute(self):
        findings = []
        secrets_ignore_patterns = glue_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = glue_client.audit_config.get("secrets_validate", False)
        connections = list(glue_client.connections)

        def payloads():
            for index, connection in enumerate(connections):
                if connection.properties:
                    yield index, json.dumps(connection.properties, indent=2)

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                payloads(),
                excluded_secrets=secrets_ignore_patterns,
                validate=validate,
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        for index, connection in enumerate(connections):
            report = Check_Report_AWS(metadata=self.metadata(), resource=connection)
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in Glue connection {connection.name}."
            )

            if connection.properties:
                if scan_error:
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Could not scan Glue connection {connection.name} "
                        f"for secrets: {scan_error}; manual review is required."
                    )
                else:
                    detect_secrets_output = batch_results.get(index)
                    if detect_secrets_output:
                        secrets_string = ", ".join(
                            f"{secret['type']} on line {secret['line_number']}"
                            for secret in detect_secrets_output
                        )
                        report.status = "FAIL"
                        report.status_extended = (
                            f"Potential secret found in Glue connection "
                            f"{connection.name} -> {secrets_string}."
                        )
                        annotate_verified_secrets(report, detect_secrets_output)

            findings.append(report)

        return findings
