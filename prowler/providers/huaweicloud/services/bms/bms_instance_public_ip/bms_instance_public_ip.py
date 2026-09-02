from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.bms.bms_client import bms_client


class bms_instance_public_ip(Check):
    """Ensure BMS instances do not have public IP addresses directly assigned."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for server in bms_client.servers.values():
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=server)
            report.region = server.region
            report.resource_id = server.id
            report.resource_arn = f"huaweicloud:bms:{server.region}:{bms_client.audited_account}:instance/{server.id}"

            if server.public_ip:
                report.status = "FAIL"
                report.status_extended = f"BMS instance {server.name} ({server.id}) has a public IP address '{server.public_ip}' directly assigned."
            else:
                report.status = "PASS"
                report.status_extended = f"BMS instance {server.name} ({server.id}) does not have a public IP address directly assigned."

            findings.append(report)

        return findings
