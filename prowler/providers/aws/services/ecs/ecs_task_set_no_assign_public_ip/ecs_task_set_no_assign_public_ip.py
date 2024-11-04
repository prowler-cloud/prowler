from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecs.ecs_client import ecs_client


class ecs_task_set_no_assign_public_ip(Check):
    def execute(self):
        findings = []
        for task_set in ecs_client.task_sets.values():
            report = Check_Report_AWS(self.metadata())
            report.region = task_set.region
            report.resource_id = task_set.id
            report.resource_arn = task_set.arn
            report.resource_tags = task_set.tags
            report.status = "PASS"
            report.status_extended = f"ECS Task Set {task_set.id} does not have automatic public IP assignment."

            if task_set.assign_public_ip == "ENABLED":
                report.status = "FAIL"
                report.status_extended = (
                    f"ECS Task Set {task_set.id} has automatic public IP assignment."
                )

            findings.append(report)
        return findings
