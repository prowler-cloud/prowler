from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.dcs.dcs_client import dcs_client


class dcs_instance_not_public(Check):
    """Check if DCS Redis instances are not publicly accessible."""

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

            if instance.publicip_address:
                report.status = "FAIL"
                report.status_extended = f"DCS instance '{instance.name}' ({instance.instance_id}) has public access enabled with IP {instance.publicip_address}."
            else:
                report.status = "PASS"
                report.status_extended = f"DCS instance '{instance.name}' ({instance.instance_id}) is not publicly accessible."

            findings.append(report)

        return findings
