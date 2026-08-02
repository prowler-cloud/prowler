from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecs.ecs_client import ecs_client


class ecs_task_definitions_logging_block_mode(Check):
    """Verify ECS task definition containers use non-blocking logging mode.

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
            containers = 0
            report.status = "PASS"
            report.status_extended = f"ECS task definition {task_definition.name} with revision {task_definition.revision} containers has logging configured with non blocking mode."
            failed_containers = []
            for container in task_definition.container_definitions:
                if container.log_driver:
                    containers = containers + 1
                    if container.log_option != "non-blocking":
                        report.status = "FAIL"
                        failed_containers.append(container.name)

            if failed_containers:
                report.status_extended = f"ECS task definition {task_definition.name} with revision {task_definition.revision} running with logging set to blocking mode on containers: {', '.join(failed_containers)}"

            if containers > 0:
                findings.append(report)
        return findings
