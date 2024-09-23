from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecs.ecs_client import ecs_client


class ecs_service_no_assign_public_ip(Check):
    def execute(self):
        findings = []
        for service in ecs_client.services.values():
            report = Check_Report_AWS(self.metadata())
            report.region = service.region
            report.resource_id = service.name
            report.resource_arn = service.arn
            report.resource_tags = service.tags
            report.status = "PASS"
            report.status_extended = f"ECS Service {service.name} does not have automatic public IP assignment."

            if service.assign_public_ip:
                report.status = "FAIL"
                report.status_extended = (
                    f"ECS Service {service.name} has automatic public IP assignment."
                )

            findings.append(report)
        return findings
