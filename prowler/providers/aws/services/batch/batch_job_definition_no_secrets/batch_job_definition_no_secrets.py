from json import dumps

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.batch.batch_client import batch_client


class batch_job_definition_no_secrets(Check):
    """Detect secrets in AWS Batch job definition environment variables and commands."""

    def execute(self) -> list[Check_Report_AWS]:
        """Scan job definitions for hardcoded secrets in env vars and commands."""
        findings = []

        secrets_ignore_patterns = batch_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = batch_client.audit_config.get("secrets_validate", False)

        job_definitions = list(batch_client.job_definitions.values())

        def scan_payloads():
            """Yield index-keyed payloads for each env var and the command."""
            for jd_index, job_definition in enumerate(job_definitions):
                container = job_definition.container_properties

                for env_index, env_var in enumerate(container.environment):
                    yield (jd_index, env_index), dumps(
                        {env_var.name: env_var.value}, indent=2
                    )

                if container.command:
                    yield (
                        (jd_index, "command"),
                        " ".join(container.command),
                    )

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                scan_payloads(),
                excluded_secrets=secrets_ignore_patterns,
                validate=validate,
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        for jd_index, job_definition in enumerate(job_definitions):
            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource=job_definition,
            )

            report.resource_id = f"{job_definition.name}:{job_definition.revision}"
            report.status = "PASS"

            extended_status_parts = []
            all_secrets = []

            container = job_definition.container_properties

            if scan_error and (container.environment or container.command):
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not scan Batch job definition "
                    f"{job_definition.name} with revision "
                    f"{job_definition.revision} for secrets: "
                    f"{scan_error}; manual review is required."
                )
                findings.append(report)
                continue

            for env_index, env_var in enumerate(container.environment):
                env_secrets = batch_results.get((jd_index, env_index))
                if env_secrets:
                    all_secrets.extend(env_secrets)
                    secrets_string = ", ".join(
                        f"{secret['type']} on the environment variable {env_var.name}"
                        for secret in env_secrets
                    )
                    extended_status_parts.append(
                        f"Secrets in environment variables -> {secrets_string}"
                    )

            if container.command:
                command_secrets = batch_results.get((jd_index, "command"))
                if command_secrets:
                    all_secrets.extend(command_secrets)
                    secrets_string = ", ".join(
                        secret["type"] for secret in command_secrets
                    )
                    extended_status_parts.append(
                        f"Secrets in command -> {secrets_string}"
                    )

            if extended_status_parts:
                report.status = "FAIL"
                report.status_extended = (
                    f"Potential secrets found in Batch job definition "
                    f"{job_definition.name} with revision "
                    f"{job_definition.revision}: "
                    + "; ".join(extended_status_parts)
                    + "."
                )
                annotate_verified_secrets(report, all_secrets)
            else:
                report.status_extended = (
                    f"No secrets found in Batch job definition "
                    f"{job_definition.name} with revision "
                    f"{job_definition.revision}."
                )

            findings.append(report)

        return findings
