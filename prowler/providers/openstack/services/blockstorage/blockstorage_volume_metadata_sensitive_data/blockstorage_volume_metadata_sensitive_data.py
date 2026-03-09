import json
from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.lib.utils.utils import detect_secrets_scan
from prowler.providers.openstack.services.blockstorage.blockstorage_client import (
    blockstorage_client,
)


class blockstorage_volume_metadata_sensitive_data(Check):
    """Ensure block storage volume metadata does not contain sensitive data like passwords or API keys."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []
        secrets_ignore_patterns = blockstorage_client.audit_config.get(
            "secrets_ignore_patterns", []
        )

        for volume in blockstorage_client.volumes:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=volume)
            report.status = "PASS"
            report.status_extended = f"Volume {volume.name} ({volume.id}) metadata does not contain sensitive data."

            if volume.metadata:
                # Build metadata dict and parallel list of keys
                dump_metadata = {}
                original_metadata_keys = []
                for key, value in volume.metadata.items():
                    dump_metadata[key] = value
                    original_metadata_keys.append(key)

                # Convert metadata dict to JSON string for detect-secrets scanning
                metadata_json = json.dumps(dump_metadata, indent=2)
                detect_secrets_output = detect_secrets_scan(
                    data=metadata_json,
                    excluded_secrets=secrets_ignore_patterns,
                    detect_secrets_plugins=blockstorage_client.audit_config.get(
                        "detect_secrets_plugins"
                    ),
                )

                if detect_secrets_output:
                    # Map line numbers back to metadata keys using the parallel list
                    # Line numbering: line 1 = "{", line 2 = first key-value, etc.
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
                    report.status_extended = f"Volume {volume.name} ({volume.id}) metadata contains potential secrets -> {secrets_string}."
            else:
                report.status_extended = f"Volume {volume.name} ({volume.id}) has no metadata (no sensitive data exposure risk)."

            findings.append(report)

        return findings
