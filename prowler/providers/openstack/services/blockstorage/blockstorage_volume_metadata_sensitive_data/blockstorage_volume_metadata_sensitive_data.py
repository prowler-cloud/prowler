import json
from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
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
        validate = blockstorage_client.audit_config.get("secrets_validate", False)
        volumes = list(blockstorage_client.volumes)

        # Collect one payload per volume (its metadata) and scan them all in
        # batched Kingfisher invocations instead of one subprocess per volume.
        def payloads():
            for index, volume in enumerate(volumes):
                if volume.metadata:
                    yield index, json.dumps(dict(volume.metadata), indent=2)

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                payloads(), excluded_secrets=secrets_ignore_patterns, validate=validate
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        for index, volume in enumerate(volumes):
            report = CheckReportOpenStack(metadata=self.metadata(), resource=volume)
            report.status = "PASS"
            report.status_extended = f"Volume {volume.name} ({volume.id}) metadata does not contain sensitive data."

            if volume.metadata:
                if scan_error:
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Could not scan volume {volume.name} ({volume.id}) metadata "
                        f"for secrets: {scan_error}; manual review is required."
                    )
                    findings.append(report)
                    continue
                original_metadata_keys = list(volume.metadata.keys())
                detect_secrets_output = batch_results.get(index)
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
                    annotate_verified_secrets(report, detect_secrets_output)
            else:
                report.status_extended = f"Volume {volume.name} ({volume.id}) has no metadata (no sensitive data exposure risk)."

            findings.append(report)

        return findings
