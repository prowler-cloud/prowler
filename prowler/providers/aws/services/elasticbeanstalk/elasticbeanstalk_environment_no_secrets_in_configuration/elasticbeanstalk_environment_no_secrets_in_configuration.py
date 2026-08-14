import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_client import (
    elasticbeanstalk_client,
)


class elasticbeanstalk_environment_no_secrets_in_configuration(Check):
    """Check that Elastic Beanstalk environments contain no hardcoded secrets in their configuration settings."""

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        secrets_ignore_patterns = elasticbeanstalk_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = elasticbeanstalk_client.audit_config.get("secrets_validate", False)
        environments = list(elasticbeanstalk_client.environments.values())
        line_context_by_env = {}

        payloads_list = []
        for env_index, environment in enumerate(environments):
            payload, line_context = _build_environment_payload(environment)
            line_context_by_env[env_index] = line_context
            if payload:
                payloads_list.append((env_index, payload))

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

        for env_index, environment in enumerate(environments):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=environment
            )
            report.resource_tags = environment.tags
            report.status = "PASS"
            report.status_extended = f"No secrets found in Elastic Beanstalk environment {environment.name} configuration settings."

            line_context = line_context_by_env.get(env_index, {})
            if line_context:
                if scan_error:
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Could not scan Elastic Beanstalk environment {environment.name} "
                        f"configuration settings for secrets: {scan_error}; manual review is required."
                    )
                    findings.append(report)
                    continue

                detect_secrets_output = batch_results.get(env_index)
                if detect_secrets_output:
                    secrets_string = ", ".join(
                        [
                            f"{secret['type']} in {line_context.get(secret['line_number'], 'configuration settings')}"
                            for secret in detect_secrets_output
                        ]
                    )
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Potential {'secrets' if len(detect_secrets_output) > 1 else 'secret'} "
                        f"found in Elastic Beanstalk environment {environment.name} configuration settings -> {secrets_string}."
                    )
                    annotate_verified_secrets(report, detect_secrets_output)

            findings.append(report)
        return findings


def _build_environment_payload(environment) -> tuple[str, dict[int, str]]:
    """Build a line-oriented scan payload and map each line to a setting context."""
    lines = []
    line_context = {}

    def add_line(context: str, value: str) -> None:
        if value is None:
            return
        lines.append(json.dumps({context: value}))
        line_context[len(lines)] = context

    for option in environment.option_settings:
        namespace = option.get("Namespace", "unknown namespace")
        option_name = option.get("OptionName", "unknown option")
        add_line(
            f"option setting '{namespace}:{option_name}'",
            option.get("Value"),
        )

    return "\n".join(lines), line_context
