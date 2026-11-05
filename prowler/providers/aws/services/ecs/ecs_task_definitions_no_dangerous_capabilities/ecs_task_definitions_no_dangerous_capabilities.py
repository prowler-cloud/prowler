from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecs.ecs_client import ecs_client

DANGEROUS_CAPABILITIES = {"SYS_ADMIN", "ALL"}


class ecs_task_definitions_no_dangerous_capabilities(Check):
    def execute(self):
        findings = []

        for task_definition in ecs_client.task_definitions.values():
            if task_definition.container_definitions is None:
                continue

            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource=task_definition,
            )
            report.resource_id = f"{task_definition.name}:{task_definition.revision}"

            dangerous_containers = []

            for container in task_definition.container_definitions:
                capabilities = set(container.added_capabilities or [])
                dangerous = capabilities & DANGEROUS_CAPABILITIES

                if dangerous:
                    dangerous_containers.append(
                        f"{container.name}: {', '.join(sorted(dangerous))}"
                    )

            if dangerous_containers:
                report.status = "FAIL"
                report.status_extended = (
                    f"ECS task definition {report.resource_id} "
                    "adds dangerous Linux capabilities: "
                    f"{'; '.join(dangerous_containers)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"ECS task definition {report.resource_id} "
                    "does not add SYS_ADMIN or ALL capabilities."
                )

            findings.append(report)

        return findings
