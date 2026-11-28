from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecs.ecs_client import ecs_client

DANGEROUS_CAPABILITIES = {"SYS_ADMIN", "ALL"}


class ecs_task_definitions_no_dangerous_capabilities(Check):
    """Check ECS task definitions for dangerous Linux capabilities."""

    def execute(self):
        """Report dangerous capabilities and unavailable ECS task data."""
        findings = []
        unavailable_task_definitions = []

        for task_definition in ecs_client.task_definitions.values():
            if task_definition.container_definitions is None:
                unavailable_task_definitions.append(
                    f"{task_definition.name}:{task_definition.revision} "
                    f"({task_definition.arn})"
                )
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

        if unavailable_task_definitions:
            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource={},
            )
            report.resource_name = "ECS task definitions"
            report.resource_id = "ecs-task-definitions-unavailable"
            report.status = "MANUAL"
            report.status_extended = (
                "Cannot evaluate ECS task definitions for dangerous Linux "
                "capabilities: container definitions could not be retrieved for "
                f"{', '.join(sorted(unavailable_task_definitions))}. "
                "Verify that ecs:DescribeTaskDefinition is granted to "
                "the scanning identity."
            )
            findings.append(report)

        failed_regions = sorted(ecs_client.task_definition_list_failed_regions)

        if failed_regions:
            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource={},
            )
            report.resource_name = "ECS task definitions"
            report.resource_id = "ecs-task-definitions-inventory-unavailable"
            report.status = "MANUAL"
            report.status_extended = (
                "Cannot evaluate ECS task definition inventory in regions: "
                f"{', '.join(failed_regions)}. "
                "Verify that ecs:ListTaskDefinitions is granted to "
                "the scanning identity and that the API is accessible."
            )
            findings.append(report)

        return findings
