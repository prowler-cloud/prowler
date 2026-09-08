from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.dcs.dcs_client import dcs_client


class dcs_instance_password_enabled(Check):
    """Check if DCS Redis instances require password authentication."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []
        for instance in dcs_client.instances:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource=instance,
            )
            report.region = instance.region
            report.resource_id = instance.instance_id
            report.resource_arn = f"huaweicloud:dcs:{instance.region}:{dcs_client.audited_account}:instance/{instance.instance_id}"

            no_password = instance.no_password_access
            if no_password == "true" or no_password is True:
                report.status = "FAIL"
                report.status_extended = f"DCS instance '{instance.name}' ({instance.instance_id}) allows access without password."
            else:
                report.status = "PASS"
                report.status_extended = f"DCS instance '{instance.name}' ({instance.instance_id}) requires password authentication."

            findings.append(report)

        return findings
