import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.datapipeline.datapipeline_client import (
    datapipeline_client,
)


class datapipeline_pipeline_no_secrets_in_definition(Check):
    """Check that AWS Data Pipeline definitions contain no hardcoded secrets."""

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Data Pipeline definition secret scan."""
        findings = []
        secrets_ignore_patterns = datapipeline_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = datapipeline_client.audit_config.get("secrets_validate", False)
        pipelines = list(datapipeline_client.pipelines.values())
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
                f"No secrets found in Data Pipeline {pipeline.name} definition."
            )

            line_context = line_context_by_pipeline.get(pipeline_index, {})
            if line_context:
                if scan_error:
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Could not scan Data Pipeline {pipeline.name} definition "
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
                        f"found in Data Pipeline {pipeline.name} definition -> {secrets_string}."
                    )
                    annotate_verified_secrets(report, detect_secrets_output)

            findings.append(report)
        return findings


def _build_definition_payload(definition: dict) -> tuple[str, dict[int, str]]:
    """Build a line-oriented scan payload and map each line to a definition field."""
    lines = []
    line_context = {}

    def add_line(context: str, value) -> None:
        if value is None:
            return
        lines.append(json.dumps({context: value}))
        line_context[len(lines)] = context

    for pipeline_object in definition.get("pipelineObjects", []):
        object_name = pipeline_object.get("name") or pipeline_object.get("id")
        for field in pipeline_object.get("fields", []):
            field_name = field.get("key")
            field_value = field.get("stringValue") or field.get("refValue")
            add_line(f"object {object_name} field {field_name}", field_value)

    for parameter_object in definition.get("parameterObjects", []):
        parameter_name = parameter_object.get("id")
        for attribute in parameter_object.get("attributes", []):
            attribute_name = attribute.get("key")
            attribute_value = attribute.get("stringValue")
            add_line(
                f"parameter object {parameter_name} attribute {attribute_name}",
                attribute_value,
            )

    for parameter_value in definition.get("parameterValues", []):
        parameter_id = parameter_value.get("id")
        add_line(f"parameter value {parameter_id}", parameter_value.get("stringValue"))

    return "\n".join(lines), line_context
