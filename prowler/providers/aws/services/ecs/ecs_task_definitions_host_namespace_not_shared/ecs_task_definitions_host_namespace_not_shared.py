from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecs.ecs_client import ecs_client


class ecs_task_definitions_host_namespace_not_shared(Check):
    """Verify ECS task definitions do not share the host process namespace with their containers.

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
            if task_definition.pid_mode == "host":
                report.status = "FAIL"
                report.status_extended = f"ECS task definition {task_definition.name} with revision {task_definition.revision} is configured to share a host's process namespace with its containers."
            else:
                report.status = "PASS"
                report.status_extended = f"ECS task definition {task_definition.name} with revision {task_definition.revision} does not share a host's process namespace with its containers."
            findings.append(report)
        return findings
