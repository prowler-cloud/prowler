from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.identitycenter.identitycenter_client import (
    identitycenter_client,
)


class identitycenter_permission_sets(Check):
    """Check whether Identity Center instances have permission sets configured."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        """Return one permission-set configuration finding per instance."""
        findings = []

        if identitycenter_client.error:
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
                "Identity Center permission sets could not be retrieved: "
                f"{identitycenter_client.error}"
            )
            findings.append(report)
        elif not identitycenter_client.instances:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource={},
            )
            report.region = identitycenter_client.region
            report.resource_id = identitycenter_client.audited_account
            report.resource_name = "Identity Center"
            report.resource_arn = ""
            report.status = "FAIL"
            report.status_extended = (
                "Identity Center is not enabled, permission sets cannot be verified."
            )
            findings.append(report)
        else:
            for instance in identitycenter_client.instances:
                report = CheckReportHuaweiCloud(
                    metadata=self.metadata(),
                    resource=instance,
                )
                report.region = identitycenter_client.region
                report.resource_id = instance.instance_id
                report.resource_name = instance.instance_id
                report.resource_arn = instance.instance_urn
                if instance.permission_sets:
                    report.status = "PASS"
                    report.status_extended = f"Identity Center instance {instance.instance_id} has {len(instance.permission_sets)} permission set(s) configured."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Identity Center instance {instance.instance_id} has no permission sets configured."
                findings.append(report)

        return findings
