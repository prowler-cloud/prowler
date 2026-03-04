import json
from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.lib.utils.utils import detect_secrets_scan
from prowler.providers.openstack.services.objectstorage.objectstorage_client import (
    objectstorage_client,
)


class objectstorage_container_metadata_sensitive_data(Check):
    """Ensure object storage container metadata does not contain sensitive data like passwords or API keys."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []
        secrets_ignore_patterns = objectstorage_client.audit_config.get(
            "secrets_ignore_patterns", []
        )

        for container in objectstorage_client.containers:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=container)
            report.status = "PASS"
            report.status_extended = (
                f"Container {container.name} metadata does not contain sensitive data."
            )

            if container.metadata:
                dump_metadata = {}
                original_metadata_keys = []
                for key, value in container.metadata.items():
                    dump_metadata[key] = value
                    original_metadata_keys.append(key)

                metadata_json = json.dumps(dump_metadata, indent=2)
                detect_secrets_output = detect_secrets_scan(
                    data=metadata_json,
                    excluded_secrets=secrets_ignore_patterns,
                    detect_secrets_plugins=objectstorage_client.audit_config.get(
                        "detect_secrets_plugins"
                    ),
                )

                if detect_secrets_output:
                    secrets_string = ", ".join(
                        [
                            f"{secret['type']} in metadata key '{original_metadata_keys[secret['line_number'] - 2]}'"
                            for secret in detect_secrets_output
                            if 0
                            <= secret["line_number"] - 2
                            < len(original_metadata_keys)
                        ]
                    )
                    report.status = "FAIL"
                    report.status_extended = f"Container {container.name} metadata contains potential secrets -> {secrets_string}."
            else:
                report.status_extended = f"Container {container.name} has no metadata (no sensitive data exposure risk)."

            findings.append(report)

        return findings
