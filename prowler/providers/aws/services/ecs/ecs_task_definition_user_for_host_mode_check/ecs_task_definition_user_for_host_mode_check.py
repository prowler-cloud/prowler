from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecs.ecs_client import ecs_client

class ecs_task_definition_user_for_host_mode_check(Check):
    def execute(self):
        findings = []

        for task_definition in ecs_client.task_definitions:
            report = Check_Report_AWS(self.metadata())
            report.region = task_definition.region
            report.resource_id = task_definition.arn
            report.resource_arn = task_definition.arn

            if task_definition.network_mode == "host":
                for container_definition in task_definition.container_definitions:
                    if container_definition.user:
                        report.status = "PASS"
                        report.status_extended = f"ECS task definition {task_definition.arn} with host mode specifies a user."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"ECS task definition {task_definition.arn} with host mode does not specify a user."
                    findings.append(report)

        return findings
