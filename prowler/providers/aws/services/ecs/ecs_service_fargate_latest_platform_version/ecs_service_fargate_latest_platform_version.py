from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecs.ecs_client import ecs_client


class ecs_service_fargate_latest_platform_version(Check):
    def execute(self):
        findings = []
        for service in ecs_client.services.values():
            if service.launch_type == "FARGATE":
                report = Check_Report_AWS(self.metadata())
                report.region = service.region
                report.resource_id = service.name
                report.resource_arn = service.arn
                report.resource_tags = service.tags
                fargate_latest_linux_version = ecs_client.audit_config.get(
                    "fargate_linux_latest_version", "1.4.0"
                )
                fargate_latest_windows_version = ecs_client.audit_config.get(
                    "fargate_windows_latest_version", "1.0.0"
                )
                report.status = "PASS"
                report.status_extended = f"ECS Service {service.name} is using latest FARGATE {service.platform_family} version {fargate_latest_linux_version if service.platform_family == 'Linux' else fargate_latest_windows_version}."
                if (
                    service.platform_version != "LATEST"
                    and (
                        service.platform_family == "Linux"
                        and service.platform_version != fargate_latest_linux_version
                    )
                    or (
                        service.platform_family == "Windows"
                        and service.platform_version != fargate_latest_windows_version
                    )
                ):
                    report.status = "FAIL"
                    report.status_extended = f"ECS Service {service.name} is not using latest FARGATE {service.platform_family} version {fargate_latest_linux_version if service.platform_family == 'Linux' else fargate_latest_windows_version}, currently using {service.platform_version}."

                findings.append(report)
        return findings
