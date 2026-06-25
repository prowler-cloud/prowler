import json
from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.lib.utils.utils import (
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
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
        validate = objectstorage_client.audit_config.get("secrets_validate", False)
        containers = list(objectstorage_client.containers)

        # Collect one payload per container (its metadata) and scan them all in
        # batched Kingfisher invocations instead of one subprocess per container.
        def payloads():
            for index, container in enumerate(containers):
                if container.metadata:
                    yield index, json.dumps(dict(container.metadata), indent=2)

        batch_results = detect_secrets_scan_batch(
            payloads(), excluded_secrets=secrets_ignore_patterns, validate=validate
        )

        for index, container in enumerate(containers):
            report = CheckReportOpenStack(metadata=self.metadata(), resource=container)
            report.status = "PASS"
            report.status_extended = (
                f"Container {container.name} metadata does not contain sensitive data."
            )

            if container.metadata:
                original_metadata_keys = list(container.metadata.keys())
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
                    report.status_extended = f"Container {container.name} metadata contains potential secrets -> {secrets_string}."
                    annotate_verified_secrets(report, detect_secrets_output)
            else:
                report.status_extended = f"Container {container.name} has no metadata (no sensitive data exposure risk)."

            findings.append(report)

        return findings
