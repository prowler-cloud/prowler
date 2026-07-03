import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.batch.batch_client import batch_client


class batch_job_definition_no_secrets(Check):
    """Check that AWS Batch job definitions contain no hardcoded secrets in their environment variables or command parameters."""

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        secrets_ignore_patterns = batch_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = batch_client.audit_config.get("secrets_validate", False)
        job_definitions = list(batch_client.job_definitions.values())
        line_context_by_jd = {}

        payloads_list = []
        for jd_index, jd in enumerate(job_definitions):
            payload, line_context = _build_job_definition_payload(jd)
            line_context_by_jd[jd_index] = line_context
            if payload:
                payloads_list.append((jd_index, payload))

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                payloads_list,
                excluded_secrets=secrets_ignore_patterns,
                validate=validate,
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        for jd_index, jd in enumerate(job_definitions):
            report = Check_Report_AWS(metadata=self.metadata(), resource=jd)
            report.resource_id = f"{jd.name}:{jd.revision}"
            report.resource_tags = jd.tags
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in Batch job definition {jd.name}."
            )

            line_context = line_context_by_jd.get(jd_index, {})
            if line_context:
                if scan_error:
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Could not scan Batch job definition {jd.name} "
                        f"for secrets: {scan_error}; manual review is required."
                    )
                    findings.append(report)
                    continue

                detect_secrets_output = batch_results.get(jd_index)
                if detect_secrets_output:
                    secrets_string = ", ".join(
                        [
                            f"{secret['type']} in {line_context.get(secret['line_number'], 'environment variables/commands')}"
                            for secret in detect_secrets_output
                        ]
                    )
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Potential {'secrets' if len(detect_secrets_output) > 1 else 'secret'} "
                        f"found in Batch job definition {jd.name} -> {secrets_string}."
                    )
                    annotate_verified_secrets(report, detect_secrets_output)

            findings.append(report)
        return findings


def _build_job_definition_payload(jd) -> tuple[str, dict[int, str]]:
    """Build a line-oriented scan payload and map each line to a field context."""
    lines = []
    line_context = {}

    def add_line(context: str, value: str) -> None:
        if not isinstance(value, str) or not value:
            return
        lines.append(json.dumps({context: value}))
        line_context[len(lines)] = context

    for container in jd.containers:
        # Scan environment variables
        for env_var in container.environment:
            name = env_var.get("name", "")
            value = env_var.get("value", "")
            add_line(
                f"container '{container.name}' environment variable '{name}'", value
            )

        # Scan command
        for idx, cmd_part in enumerate(container.command):
            add_line(
                f"container '{container.name}' command parameter at index {idx}",
                cmd_part,
            )

    return "\n".join(lines), line_context
