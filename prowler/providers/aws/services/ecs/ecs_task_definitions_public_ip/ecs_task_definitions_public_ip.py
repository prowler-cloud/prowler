from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecs.ecs_client import ecs_client


class ecs_task_definitions_public_ip(Check):
    def execute(self):
        findings = []
        for task_definition in ecs_client.task_definitions:
            report = Check_Report_AWS(self.metadata())
            report.region = task_definition.region
            report.resource_id = f"{task_definition.name}:{task_definition.revision}"
            report.resource_arn = task_definition.arn
            report.resource_tags = task_definition.tags
            report.status = "PASS"
            report.status_extended = f"{task_definition.name} with no \"awsvpc\" network mode in use, that implies a public IP assign to the running task."
            if task_definition.network_mode == "awsvpc":
                report.status = "FAIL"
                report.status_extended = f"{task_definition.name} with \"awsvpc\" network mode in use, that implies a public IP assign to the running task."
            findings.append(report)

        return findings
