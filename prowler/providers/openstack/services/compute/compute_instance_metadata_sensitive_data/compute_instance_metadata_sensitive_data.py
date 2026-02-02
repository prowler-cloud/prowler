import json
from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.lib.utils.utils import detect_secrets_scan
from prowler.providers.openstack.services.compute.compute_client import compute_client


class compute_instance_metadata_sensitive_data(Check):
    """Ensure compute instance metadata does not contain sensitive data like passwords or API keys."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []
        secrets_ignore_patterns = compute_client.audit_config.get(
            "secrets_ignore_patterns", []
        )

        for instance in compute_client.instances:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=instance)
            report.status = "PASS"
            report.status_extended = f"Instance {instance.name} ({instance.id}) metadata does not contain sensitive data."

            if instance.metadata:
                # Convert metadata dict to JSON string for detect-secrets scanning
                metadata_json = json.dumps(instance.metadata, indent=2)
                detect_secrets_output = detect_secrets_scan(
                    data=metadata_json,
                    excluded_secrets=secrets_ignore_patterns,
                    detect_secrets_plugins=compute_client.audit_config.get(
                        "detect_secrets_plugins"
                    ),
                )

                if detect_secrets_output:
                    # Map line numbers back to metadata keys
                    metadata_keys = list(instance.metadata.keys())
                    secrets_string = ", ".join(
                        [
                            (
                                f"{secret['type']} in metadata key '{metadata_keys[(secret['line_number'] - 2) // 2]}'"
                                if (secret["line_number"] - 2) // 2 < len(metadata_keys)
                                else f"{secret['type']} on line {secret['line_number']}"
                            )
                            for secret in detect_secrets_output
                        ]
                    )
                    report.status = "FAIL"
                    report.status_extended = f"Instance {instance.name} ({instance.id}) metadata contains potential secrets -> {secrets_string}."
            else:
                report.status_extended = f"Instance {instance.name} ({instance.id}) has no metadata (no sensitive data exposure risk)."

            findings.append(report)

        return findings
