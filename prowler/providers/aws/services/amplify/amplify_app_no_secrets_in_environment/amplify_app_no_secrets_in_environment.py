import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.amplify.amplify_client import amplify_client


class amplify_app_no_secrets_in_environment(Check):
    """Check that AWS Amplify apps contain no hardcoded secrets in their environment variables or build settings."""

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        secrets_ignore_patterns = amplify_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = amplify_client.audit_config.get("secrets_validate", False)
        apps = list(amplify_client.apps.values())
        line_context_by_app = {}

        payloads_list = []
        for app_index, app in enumerate(apps):
            payload, line_context = _build_app_payload(app)
            line_context_by_app[app_index] = line_context
            if payload:
                payloads_list.append((app_index, payload))

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

        for app_index, app in enumerate(apps):
            report = Check_Report_AWS(metadata=self.metadata(), resource=app)
            report.resource_tags = app.tags
            report.status = "PASS"
            report.status_extended = f"No secrets found in Amplify app {app.name} environment variables or build settings."

            line_context = line_context_by_app.get(app_index, {})
            if line_context:
                if scan_error:
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Could not scan Amplify app {app.name} environment variables "
                        f"for secrets: {scan_error}; manual review is required."
                    )
                    findings.append(report)
                    continue

                detect_secrets_output = batch_results.get(app_index)
                if detect_secrets_output:
                    secrets_string = ", ".join(
                        [
                            f"{secret['type']} in {line_context.get(secret['line_number'], 'environment variables/build settings')}"
                            for secret in detect_secrets_output
                        ]
                    )
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Potential {'secrets' if len(detect_secrets_output) > 1 else 'secret'} "
                        f"found in Amplify app {app.name} environment variables or build settings -> {secrets_string}."
                    )
                    annotate_verified_secrets(report, detect_secrets_output)

            findings.append(report)
        return findings


def _build_app_payload(app) -> tuple[str, dict[int, str]]:
    """Build a line-oriented scan payload and map each line to a field context."""
    lines = []
    line_context = {}

    def add_line(context: str, value: str) -> None:
        if value is None:
            return
        lines.append(json.dumps({context: value}))
        line_context[len(lines)] = context

    # App environment variables
    for var_name, var_value in app.environment_variables.items():
        add_line(f"app environment variable '{var_name}'", var_value)

    # App buildSpec
    if app.build_spec:
        for idx, line in enumerate(app.build_spec.splitlines(), start=1):
            add_line(f"app buildSpec line {idx}", line)

    # Branch environment variables
    for branch in app.branches:
        for var_name, var_value in branch.environment_variables.items():
            add_line(
                f"branch '{branch.name}' environment variable '{var_name}'", var_value
            )

    return "\n".join(lines), line_context
