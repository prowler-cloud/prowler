from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecs.ecs_client import ecs_client


class ecs_task_definitions_logging_enabled(Check):
    def execute(self):
        findings = []
        for task_definition in ecs_client.task_definitions.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=task_definition
            )
            report.resource_id = f"{task_definition.name}:{task_definition.revision}"
            report.status = "PASS"
            report.status_extended = f"ECS task definition {task_definition.name} with revision {task_definition.revision} containers have logging configured."
            failed_containers = []
            for container in task_definition.container_definitions:
                if not container.log_driver:
                    report.status = "FAIL"
                    failed_containers.append(container.name)

            if failed_containers:
                report.status_extended = f"ECS task definition {task_definition.name} with revision {task_definition.revision} has containers running with no logging configuration: {', '.join(failed_containers)}"

            findings.append(report)
        return findings
