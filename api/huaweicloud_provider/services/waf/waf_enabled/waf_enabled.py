from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.waf.waf_client import waf_client


class waf_enabled(Check):
    """Check if WAF (Web Application Firewall) is enabled."""

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
                    f"huaweicloud:waf:{instance.region}:{waf_client.audited_account}:instance/{instance.id}"
                )

                # status: 0 = creating, 1 = running, 2 = deleting, 3 = deleted, 4 = abnormal, 5 = freezing
                if instance.status == 1:
                    report.status = "PASS"
                    report.status_extended = (
                        f"WAF instance {instance.name} ({instance.id}) "
                        f"is enabled and running."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"WAF instance {instance.name} ({instance.id}) "
                        f"is not running (status: {instance.status})."
                    )

                findings.append(report)
        else:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(), resource={}
            )
            report.region = waf_client.region
            report.resource_id = "waf"
            report.resource_arn = (
                f"huaweicloud:waf:{waf_client.region}:{waf_client.audited_account}:waf/global"
            )
            report.status = "FAIL"
            report.status_extended = (
                "No WAF instances found. Web Application Firewall is not enabled."
            )
            findings.append(report)

        return findings
