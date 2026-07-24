from json import dumps

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.batch.batch_client import batch_client


class batch_job_definition_no_secrets(Check):
    def execute(self):
        findings = []

        secrets_ignore_patterns = batch_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = batch_client.audit_config.get(
            "secrets_validate", False
        )

        job_definitions = batch_client.job_definitions

        def scan_payloads():
            for jd_index, job_definition in enumerate(job_definitions):
                container = job_definition.container_properties

                if container.environment:
                    dump_env_vars = {
                        env_var.name: env_var.value
                        for env_var in container.environment
                    }
                    yield (jd_index, "environment"), dumps(
                        dump_env_vars, indent=2
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

            report.resource_id = (
                f"{job_definition.name}:{job_definition.revision}"
            )
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

            if container.environment:
                original_env_vars = [
                    env_var.name for env_var in container.environment
                ]

                env_secrets = batch_results.get(
                    (jd_index, "environment")
                )
                if env_secrets:
                    all_secrets.extend(env_secrets)
                    secrets_string = ", ".join(
                        f"{secret['type']} on the environment variable {original_env_vars[secret['line_number'] - 2]}"
                        for secret in env_secrets
                    )
                    extended_status_parts.append(
                        f"Secrets in environment variables -> {secrets_string}"
                    )

            if container.command:
                command_secrets = batch_results.get(
                    (jd_index, "command")
                )
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
