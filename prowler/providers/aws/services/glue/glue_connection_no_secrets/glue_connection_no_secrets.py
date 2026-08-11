import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.glue.glue_client import glue_client


class glue_connection_no_secrets(Check):
    """Check if Glue connections have secrets in their connection properties.

    Scans the ConnectionProperties of each AWS Glue connection for hardcoded
    credentials, tokens, passwords, and other sensitive values.

    Glue connection properties frequently carry JDBC connection strings,
    usernames, and passwords for databases (RDS, Redshift, on-premises).
    These values are visible in the console, CLI output, and CloudTrail logs.
    Secrets should be stored in AWS Secrets Manager or Systems Manager
    Parameter Store and referenced by ARN/name rather than embedded inline.

    Reference API: glue:GetConnections → ConnectionProperties dict.
    """

    def execute(self):
        findings = []
        secrets_ignore_patterns = glue_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = glue_client.audit_config.get("secrets_validate", False)
        connections = list(glue_client.connections)

        # Scan every property value across all connections in batched invocations
        # to avoid spawning one subprocess per property. Keys are
        # (connection_index, property_key) so results can be mapped back to the
        # originating connection and the specific property that triggered the hit.
        def payloads():
            for conn_index, conn in enumerate(connections):
                for prop_key, prop_value in conn.properties.items():
                    if prop_value:
                        yield (
                            conn_index,
                            prop_key,
                        ), json.dumps({prop_key: prop_value})

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

        for conn_index, conn in enumerate(connections):
            report = Check_Report_AWS(metadata=self.metadata(), resource=conn)
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in Glue connection {conn.name} properties."
            )

            # If the scan utility itself failed and this connection has properties,
            # flag for manual review instead of silently passing — a missed secret
            # in a database connection is worse than a false-positive alert.
            if conn.properties and scan_error:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not scan Glue connection {conn.name} properties for "
                    f"secrets: {scan_error}; manual review is required."
                )
                findings.append(report)
                continue

            if conn.properties:
                secrets_found = []
                all_secrets = []
                for prop_key in conn.properties:
                    detect_secrets_output = batch_results.get(
                        (conn_index, prop_key)
                    )
                    if detect_secrets_output:
                        all_secrets.extend(detect_secrets_output)
                        secrets_found.extend(
                            [
                                f"{secret['type']} in property {prop_key}"
                                for secret in detect_secrets_output
                            ]
                        )

                if secrets_found:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Potential secrets found in Glue connection {conn.name} "
                        f"properties: {', '.join(secrets_found)}."
                    )
                    annotate_verified_secrets(report, all_secrets)

            findings.append(report)

        return findings
