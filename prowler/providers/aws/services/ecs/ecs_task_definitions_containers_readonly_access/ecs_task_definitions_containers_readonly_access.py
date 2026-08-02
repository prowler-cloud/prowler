from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecs.ecs_client import ecs_client


class ecs_task_definitions_containers_readonly_access(Check):
    """Verify ECS task definition containers do not have write access to their root filesystems.

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
                if not container.readonly_rootfilesystem
            ]
            if failed_containers:
                report.status = "FAIL"
                report.status_extended = f"ECS task definition {task_definition.name} with revision {task_definition.revision} has containers with write access to the root filesystem: {', '.join(failed_containers)}"
            else:
                report.status = "PASS"
                report.status_extended = f"ECS task definition {task_definition.name} with revision {task_definition.revision} does not have containers with write access to the root filesystems."
            findings.append(report)

        return findings
