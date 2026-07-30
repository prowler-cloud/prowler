import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.glue.glue_client import glue_client


class glue_catalog_connection_no_secrets(Check):
    """Check if Glue Data Catalog connections store secrets in ConnectionProperties.

    Scans the ConnectionProperties of each Data Catalog connection for
    hardcoded credentials, tokens, passwords, and other sensitive values that
    should be stored in Secrets Manager or Parameter Store instead.
    """

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        secrets_ignore_patterns = glue_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = glue_client.audit_config.get("secrets_validate", False)
        connections = list(glue_client.connections)

        # Collect every connection property across all connections and scan them
        # in batched Kingfisher invocations instead of one subprocess per
        # property. Findings are keyed by (connection index, property name) so a
        # detected secret is reported against the exact property it came from.
        def payloads():
            for conn_index, connection in enumerate(connections):
                if connection.properties:
                    for prop_name, prop_value in connection.properties.items():
                        yield (conn_index, prop_name), json.dumps(
                            {prop_name: prop_value}
                        )

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                payloads(), excluded_secrets=secrets_ignore_patterns, validate=validate
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        for conn_index, connection in enumerate(connections):
            report = Check_Report_AWS(metadata=self.metadata(), resource=connection)
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in Glue Data Catalog connection "
                f"{connection.name} properties."
            )

            if connection.properties and scan_error:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not scan Glue Data Catalog connection {connection.name} "
                    f"properties for secrets: {scan_error}; manual review is required."
                )
                findings.append(report)
                continue

            if connection.properties:
                secrets_found = []
                all_secrets = []
                for prop_name in connection.properties:
                    detect_secrets_output = batch_results.get((conn_index, prop_name))
                    if detect_secrets_output:
                        all_secrets.extend(detect_secrets_output)
                        secrets_found.extend(
                            [
                                f"{secret['type']} in property {prop_name}"
                                for secret in detect_secrets_output
                            ]
                        )

                if secrets_found:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Potential secrets found in Glue Data Catalog connection "
                        f"{connection.name} properties: {', '.join(secrets_found)}."
                    )
                    annotate_verified_secrets(report, all_secrets)

            findings.append(report)

        return findings
