from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.cfw.cfw_client import cfw_client


class cfw_firewall_enabled(Check):
    """Check if Cloud Firewall is enabled and active."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        if not cfw_client.firewalls:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource={},
            )
            report.region = cfw_client.region
            report.resource_id = "Cloud Firewall"
            report.resource_arn = (
                f"huaweicloud:cfw:{cfw_client.region}:{cfw_client.audited_account}:firewall"
            )
            report.status = "FAIL"
            report.status_extended = (
                "No Cloud Firewall deployed. Network traffic is not being inspected."
            )
            findings.append(report)
            return findings

        for firewall in cfw_client.firewalls:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource=firewall,
            )
            report.region = firewall.region
            report.resource_id = firewall.fw_instance_id
            report.resource_arn = f"huaweicloud:cfw:{firewall.region}:{cfw_client.audited_account}:firewall/{firewall.fw_instance_id}"

            if firewall.status == "1":
                report.status = "PASS"
                report.status_extended = (
                    f"Cloud Firewall '{firewall.name}' ({firewall.fw_instance_id}) is active."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Cloud Firewall '{firewall.name}' ({firewall.fw_instance_id}) "
                    f"is not active (status: {firewall.status})."
                )

            findings.append(report)

        return findings
