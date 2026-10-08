from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.dcs.dcs_client import dcs_client


class dcs_instance_ssl_enabled(Check):
    """Check if DCS Redis instances have SSL/TLS encryption enabled."""

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

            if instance.enable_ssl is False:
                report.status = "FAIL"
                report.status_extended = f"DCS instance '{instance.name}' ({instance.instance_id}) does not have SSL/TLS encryption enabled."
            else:
                report.status = "PASS"
                report.status_extended = f"DCS instance '{instance.name}' ({instance.instance_id}) has SSL/TLS encryption enabled."

            findings.append(report)

        return findings
