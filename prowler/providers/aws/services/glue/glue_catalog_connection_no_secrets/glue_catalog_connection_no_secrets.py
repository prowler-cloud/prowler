import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.glue.glue_client import glue_client


class glue_catalog_connection_no_secrets(Check):
    """Check if Glue Data Catalog connections have secrets in their properties.

    Scans the ConnectionProperties of each Data Catalog connection for
    hardcoded credentials, tokens, passwords, and other sensitive values that
    should be stored in Secrets Manager or Parameter Store instead.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Scan every Glue Data Catalog connection's properties for secrets.

        Returns:
            One Check_Report_AWS per connection, with status PASS when no
            secrets are detected, FAIL when a property resembles a secret,
            or MANUAL when the secret scan could not be completed.
        """
        findings = []
        secrets_ignore_patterns = glue_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = glue_client.audit_config.get("secrets_validate", False)
        connections = list(glue_client.connections)

        # Scan each connection's properties as a single indented-JSON payload so
        # every property value sits on its own line; a finding is mapped back to
        # its property via the finding's line number. Findings are keyed by
        # connection index.
        def payloads():
            for conn_index, conn in enumerate(connections):
                if conn.properties:
                    yield (conn_index, json.dumps(conn.properties, indent=2))

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                payloads(), excluded_secrets=secrets_ignore_patterns, validate=validate
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        for conn_index, conn in enumerate(connections):
            report = Check_Report_AWS(metadata=self.metadata(), resource=conn)
            report.status = "PASS"
            report.status_extended = f"No secrets found in Glue Data Catalog connection {conn.name} properties."

            if conn.properties:
                if scan_error:
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Could not scan Glue Data Catalog connection {conn.name} "
                        f"properties for secrets: {scan_error}; manual review is required."
                    )
                    findings.append(report)
                    continue

                detect_secrets_output = batch_results.get(conn_index)
                if detect_secrets_output:
                    property_names = list(conn.properties.keys())
                    secrets_string = ", ".join(
                        [
                            f"{secret['type']} in property "
                            f"{property_names[secret['line_number'] - 2]}"
                            for secret in detect_secrets_output
                        ]
                    )
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Potential "
                        f"{'secrets' if len(detect_secrets_output) > 1 else 'secret'} "
                        f"found in Glue Data Catalog connection {conn.name} "
                        f"properties: {secrets_string}."
                    )
                    annotate_verified_secrets(report, detect_secrets_output)

            findings.append(report)

        return findings
