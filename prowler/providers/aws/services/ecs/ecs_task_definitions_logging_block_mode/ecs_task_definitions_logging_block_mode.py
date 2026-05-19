from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.check.resource_limit import get_resource_scan_limit, limited_findings
from prowler.providers.aws.services.ecs.ecs_client import ecs_client


class ecs_task_definitions_logging_block_mode(Check):
    def execute(self):
        def evaluate(task_definition):
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

            # Only task definitions with logging-enabled containers are reported
            return report if containers > 0 else None

        return limited_findings(
            ecs_client.iter_task_definitions(),
            evaluate,
            get_resource_scan_limit(
                ecs_client.audit_config, "max_ecs_task_definitions"
            ),
        )
