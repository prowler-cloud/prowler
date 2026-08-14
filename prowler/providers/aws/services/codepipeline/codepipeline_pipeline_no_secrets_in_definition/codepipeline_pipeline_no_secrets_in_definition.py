import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.codepipeline.codepipeline_client import (
    codepipeline_client,
)


class codepipeline_pipeline_no_secrets_in_definition(Check):
    """Check that AWS CodePipeline pipeline definitions contain no hardcoded secrets."""

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the CodePipeline definition secret scan."""
        findings = []
        secrets_ignore_patterns = codepipeline_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = codepipeline_client.audit_config.get("secrets_validate", False)
        pipelines = list(codepipeline_client.pipelines.values())
        line_context_by_pipeline = {}
        payloads = []
        for pipeline_index, pipeline in enumerate(pipelines):
            payload, line_context = _build_definition_payload(pipeline.definition)
            line_context_by_pipeline[pipeline_index] = line_context
            if payload:
                payloads.append((pipeline_index, payload))

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                payloads, excluded_secrets=secrets_ignore_patterns, validate=validate
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        for pipeline_index, pipeline in enumerate(pipelines):
            report = Check_Report_AWS(metadata=self.metadata(), resource=pipeline)
            report.resource_tags = pipeline.tags
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in CodePipeline {pipeline.name} definition."
            )

            line_context = line_context_by_pipeline.get(pipeline_index, {})
            if line_context:
                if scan_error:
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Could not scan CodePipeline {pipeline.name} definition "
                        f"for secrets: {scan_error}; manual review is required."
                    )
                    findings.append(report)
                    continue

                detect_secrets_output = batch_results.get(pipeline_index)
                if detect_secrets_output:
                    secrets_string = ", ".join(
                        [
                            f"{secret['type']} in {line_context.get(secret['line_number'], 'definition')}"
                            for secret in detect_secrets_output
                        ]
                    )
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Potential {'secrets' if len(detect_secrets_output) > 1 else 'secret'} "
                        f"found in CodePipeline {pipeline.name} definition -> {secrets_string}."
                    )
                    annotate_verified_secrets(report, detect_secrets_output)

            findings.append(report)
        return findings


def _build_definition_payload(definition: list) -> tuple[str, dict[int, str]]:
    """Build a line-oriented scan payload and map each line to a definition field.

    Iterates over every stage/action configuration in the pipeline definition and
    emits one JSON line per configuration value so that Kingfisher can scan each
    value independently and map findings back to the originating stage/action.
    """
    lines = []
    line_context = {}

    def add_line(context: str, value) -> None:
        if value is None:
            return
        lines.append(json.dumps({context: value}))
        line_context[len(lines)] = context

    for stage in definition:
        stage_name = stage.get("name", "stage")
        for action in stage.get("actions", []):
            action_name = action.get("name", "action")
            configuration = action.get("configuration", {})
            for config_key, config_value in configuration.items():
                add_line(
                    f"stage {stage_name} action {action_name} configuration {config_key}",
                    config_value,
                )

    return "\n".join(lines), line_context
