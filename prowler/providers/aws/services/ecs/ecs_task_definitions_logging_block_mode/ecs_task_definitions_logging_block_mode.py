from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecs.ecs_client import ecs_client


class ecs_task_definitions_logging_block_mode(Check):
    def execute(self):
        findings = []
        for task_definition in ecs_client.task_definitions.values():
            report = Check_Report_AWS(self.metadata())
            containers = 0
            report.region = task_definition.region
            report.resource_id = f"{task_definition.name}:{task_definition.revision}"
            report.resource_arn = task_definition.arn
            report.resource_tags = task_definition.tags
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
