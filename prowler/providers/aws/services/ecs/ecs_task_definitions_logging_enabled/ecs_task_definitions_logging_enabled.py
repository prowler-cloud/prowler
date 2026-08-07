from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecs.ecs_client import ecs_client


class ecs_task_definitions_logging_enabled(Check):
    """Verify ECS task definition containers have logging configured.

    Task definitions whose describe call failed are skipped so an
    unexamined resource is never reported as compliant.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check.

        Returns:
            A list of check reports, one per ECS task definition.
        """
        findings = []
        for task_definition in ecs_client.task_definitions.values():
            if task_definition.container_definitions is None:
                continue
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=task_definition
            )
            report.resource_id = f"{task_definition.name}:{task_definition.revision}"

            failed_containers = [
                container.name
                for container in task_definition.container_definitions
                if not container.log_driver
            ]
            if failed_containers:
                report.status = "FAIL"
                report.status_extended = f"ECS task definition {task_definition.name} with revision {task_definition.revision} has containers running with no logging configuration: {', '.join(failed_containers)}"
            else:
                report.status = "PASS"
                report.status_extended = f"ECS task definition {task_definition.name} with revision {task_definition.revision} containers have logging configured."
            findings.append(report)
        return findings
