from json import dumps

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.ecs.ecs_client import ecs_client


class ecs_task_definitions_no_environment_secrets(Check):
    def execute(self):
        findings = []
        secrets_ignore_patterns = ecs_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = ecs_client.audit_config.get("secrets_validate", False)
        task_definitions = list(ecs_client.task_definitions.values())

        # Scan every (task definition, container) environment in batched
        # Kingfisher invocations instead of one subprocess per container.
        # Payloads are yielded lazily so only a chunk is held/written at a time.
        def environment_payloads():
            for td_index, task_definition in enumerate(task_definitions):
                for c_index, container in enumerate(
                    task_definition.container_definitions
                ):
                    if container.environment:
                        dump_env_vars = {
                            env_var.name: env_var.value
                            for env_var in container.environment
                        }
                        yield (td_index, c_index), dumps(dump_env_vars, indent=2)

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                environment_payloads(),
                excluded_secrets=secrets_ignore_patterns,
                validate=validate,
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        for td_index, task_definition in enumerate(task_definitions):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=task_definition
            )
            report.resource_id = f"{task_definition.name}:{task_definition.revision}"
            report.status = "PASS"
            extended_status_parts = []
            all_secrets = []

            if scan_error and any(
                container.environment
                for container in task_definition.container_definitions
            ):
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not scan ECS task definition {task_definition.name} with "
                    f"revision {task_definition.revision} for secrets: {scan_error}; "
                    "manual review is required."
                )
                findings.append(report)
                continue

            for c_index, container in enumerate(task_definition.container_definitions):
                container_secrets_found = []

                if container.environment:
                    original_env_vars = [
                        env_var.name for env_var in container.environment
                    ]
                    detect_secrets_output = batch_results.get((td_index, c_index))
                    if detect_secrets_output:
                        all_secrets.extend(detect_secrets_output)
                        secrets_string = ", ".join(
                            [
                                f"{secret['type']} on the environment variable {original_env_vars[secret['line_number'] - 2]}"
                                for secret in detect_secrets_output
                            ]
                        )
                        container_secrets_found.append(
                            f"Secrets in container {container.name} -> {secrets_string}"
                        )
                if container_secrets_found:
                    report.status = "FAIL"
                    extended_status_parts.extend(container_secrets_found)
            if report.status == "FAIL":
                report.status_extended = (
                    f"Potential secrets found in ECS task definition {task_definition.name} with revision {task_definition.revision}: "
                    + "; ".join(extended_status_parts)
                    + "."
                )
                annotate_verified_secrets(report, all_secrets)
            else:
                report.status_extended = f"No secrets found in variables of ECS task definition {task_definition.name} with revision {task_definition.revision}."
            findings.append(report)

        return findings
