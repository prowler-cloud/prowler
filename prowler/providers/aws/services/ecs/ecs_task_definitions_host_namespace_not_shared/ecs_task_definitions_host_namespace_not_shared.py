from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecs.ecs_client import ecs_client


class ecs_task_definitions_host_namespace_not_shared(Check):
    def execute(self):
        findings = []
        for task_definition in ecs_client.task_definitions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = task_definition.region
            report.resource_id = f"{task_definition.name}:{task_definition.revision}"
            report.resource_arn = task_definition.arn
            report.resource_tags = task_definition.tags
            report.status = "PASS"
            report.status_extended = f"ECS task definition {task_definition.name} with revision {task_definition.revision} does not share a host's process namespace with its containers."
            if task_definition.pid_mode == "host":
                report.status = "FAIL"
                report.status_extended = f"ECS task definition {task_definition.name} with revision {task_definition.revision} is configured to share a host's process namespace with its containers."
            findings.append(report)
        return findings
