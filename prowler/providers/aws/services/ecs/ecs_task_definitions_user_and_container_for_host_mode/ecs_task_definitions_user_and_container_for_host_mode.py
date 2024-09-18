from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecs.ecs_client import ecs_client


class ecs_task_definitions_user_and_container_for_host_mode(Check):
    def execute(self):
        findings = []
        for task_definition in ecs_client.task_definitions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = task_definition.region
            report.resource_id = f"{task_definition.name}:{task_definition.revision}"
            report.resource_arn = task_definition.arn
            report.resource_tags = task_definition.tags
            report.status = "PASS"
            container_statuses = []
            if task_definition.network_mode == "host":
                for container in task_definition.container_definitions:
                    if not container.privileged and (
                        container.user == "root" or container.user == ""
                    ):
                        report.status = "FAIL"
                        container_statuses.append(
                            f"Container '{container.name}' is running as root user but is not privileged."
                        )

                if container_statuses:
                    report.status_extended = (
                        f"ECS task definition '{task_definition.name}' with host network mode has issues:"
                        + " ".join(container_statuses)
                    )
                else:
                    report.status_extended = f"ECS task definition '{task_definition.name}' has host network mode but there are no issues with container definitions."
            else:
                report.status_extended = f"ECS task definition '{task_definition.name}' does not have host network mode."
        return findings
