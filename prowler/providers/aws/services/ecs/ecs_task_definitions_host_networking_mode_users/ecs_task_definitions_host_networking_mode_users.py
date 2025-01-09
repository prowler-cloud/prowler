from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecs.ecs_client import ecs_client


class ecs_task_definitions_host_networking_mode_users(Check):
    def execute(self):
        findings = []
        for task_definition in ecs_client.task_definitions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = task_definition.region
            report.resource_id = f"{task_definition.name}:{task_definition.revision}"
            report.resource_arn = task_definition.arn
            report.resource_tags = task_definition.tags
            report.status = "PASS"
            report.status_extended = f"ECS task definition {task_definition.name} with revision {task_definition.revision} does not have host network mode."
            failed_containers = []
            if task_definition.network_mode == "host":
                for container in task_definition.container_definitions:
                    if not container.privileged and (
                        container.user == "root" or container.user == ""
                    ):
                        report.status = "FAIL"
                        failed_containers.append(container.name)

                if failed_containers:
                    report.status_extended = f"ECS task definition {task_definition.name} with revision {task_definition.revision} has containers with host network mode and non-privileged containers running as root or with no user specified: {', '.join(failed_containers)}"
                else:
                    report.status_extended = f"ECS task definition {task_definition.name} with revision {task_definition.revision} has host network mode but no containers running as root or with no user specified."
            findings.append(report)
        return findings
