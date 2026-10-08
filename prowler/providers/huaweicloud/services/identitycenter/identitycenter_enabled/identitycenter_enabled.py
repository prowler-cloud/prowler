from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.identitycenter.identitycenter_client import (
    identitycenter_client,
)


class identitycenter_enabled(Check):
    """Check whether Huawei Cloud Identity Center is enabled."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        """Return PASS for instances, FAIL when disabled, or MANUAL on errors."""
        findings = []

        if identitycenter_client.instances:
            for instance in identitycenter_client.instances:
                report = CheckReportHuaweiCloud(
                    metadata=self.metadata(),
                    resource=instance,
                )
                report.region = identitycenter_client.region
                report.resource_id = instance.instance_id
                report.resource_name = instance.instance_id
                report.resource_arn = instance.instance_urn
                report.status = "PASS"
                report.status_extended = (
                    f"Identity Center is enabled with instance {instance.instance_id}."
                )
                findings.append(report)
        elif identitycenter_client.error:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource={},
            )
            report.region = identitycenter_client.region
            report.resource_id = identitycenter_client.audited_account
            report.resource_name = "Identity Center"
            report.resource_arn = ""
            report.status = "MANUAL"
            report.status_extended = (
                "Identity Center instances could not be retrieved: "
                f"{identitycenter_client.error}"
            )
            findings.append(report)
        else:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource={},
            )
            report.region = identitycenter_client.region
            report.resource_id = identitycenter_client.audited_account
            report.resource_name = "Identity Center"
            report.resource_arn = ""
            report.status = "FAIL"
            report.status_extended = "Identity Center is not enabled."
            findings.append(report)

        return findings
