from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecs.ecs_client import ecs_client
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class ecs_container_not_directly_publicly_accessible_via_elbv2(Check):
    def execute(self):
        findings = []

        if ecs_client.containers:
            public_containers = {}
            for tg in elbv2_client.target_groups:
                if tg.public and tg.target_type == "ip":
                    public_containers[tg.target] = tg.arn

            for container in ecs_client.containers:
                report = Check_Report_AWS(self.metadata())
                report.resource_arn = container.arn
                report.resource_tags = container.tags
                report.status = "PASS"
                report.status_extended = f"ECS Container {container.arn} is not behind an Internet facing Load Balancer."

                # if the container private ip of the public lb is the same as the instances that are active, fail
                if container.ipv4 in public_containers:
                    report.status = "FAIL"
                    report.status_extended = f"ECS Container {container.arn} is behind an Internet facing Load Balancer through target group {public_containers[container.ipv4]}."
                elif container.ipv6 in public_containers:
                    report.status = "FAIL"
                    report.status_extended = f"ECS Container {container.arn} is behind an Internet facing Load Balancer through target group {public_containers[container.ipv6]}."
                findings.append(report)
        return findings