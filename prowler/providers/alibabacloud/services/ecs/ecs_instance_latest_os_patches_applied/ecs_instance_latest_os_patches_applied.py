from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ecs.ecs_client import ecs_client
from prowler.providers.alibabacloud.services.securitycenter.securitycenter_client import (
    securitycenter_client,
)


class ecs_instance_latest_os_patches_applied(Check):
    """Check if the latest OS patches for all Virtual Machines are applied."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        # Check each ECS instance for vulnerabilities
        for instance in ecs_client.instances:
            # Only check running instances
            if instance.status.lower() not in ["running", "starting"]:
                continue

            report = CheckReportAlibabaCloud(
                metadata=self.metadata(), resource=instance
            )
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = f"acs:ecs:{instance.region}:{ecs_client.audited_account}:instance/{instance.id}"

            # Check if instance has vulnerabilities
            instance_key = f"{instance.region}:{instance.id}"
            vulnerability = securitycenter_client.instance_vulnerabilities.get(
                instance_key
            )

            if vulnerability:
                if vulnerability.has_vulnerabilities:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"ECS instance {instance.name if instance.name else instance.id} "
                        f"has {vulnerability.vulnerability_count} unpatched vulnerabilities. "
                        "Latest OS patches are not applied."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"ECS instance {instance.name if instance.name else instance.id} "
                        "has all latest OS patches applied."
                    )

                findings.append(report)

        return findings
