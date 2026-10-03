from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.waf.waf_client import waf_client


class waf_instance_configured(Check):
    """Check if at least one WAF instance is configured."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        if waf_client.instances:
            for instance in waf_client.instances:
                report = CheckReportHuaweiCloud(
                    metadata=self.metadata(), resource=instance
                )
                report.region = instance.region
                report.resource_id = instance.id
                report.resource_arn = (
                    f"huaweicloud:waf:{instance.region}:"
                    f"{waf_client.audited_account}:instance/{instance.id}"
                )
                report.status = "PASS"
                report.status_extended = (
                    f"WAF instance {instance.name} ({instance.id}) " f"is configured."
                )
                findings.append(report)
        else:
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource={})
            report.region = waf_client.region
            report.resource_id = ""
            report.resource_arn = ""
            report.status = "FAIL"
            report.status_extended = "No WAF instances are configured."
            findings.append(report)

        return findings
