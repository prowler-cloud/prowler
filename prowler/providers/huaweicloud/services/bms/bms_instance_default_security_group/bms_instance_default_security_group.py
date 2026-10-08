from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.bms.bms_client import bms_client


class bms_instance_default_security_group(Check):
    """Ensure BMS instances are not using the default security group."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for server in bms_client.servers.values():
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=server)
            report.region = server.region
            report.resource_id = server.id
            report.resource_arn = f"huaweicloud:bms:{server.region}:{bms_client.audited_account}:instance/{server.id}"

            default_sg_names = {"default", "sys_default"}
            using_default = any(
                sg_name in default_sg_names
                for sg_name in server.security_groups.values()
            )

            if using_default:
                report.status = "FAIL"
                report.status_extended = f"BMS instance {server.name} ({server.id}) is using the default security group."
            else:
                report.status = "PASS"
                report.status_extended = f"BMS instance {server.name} ({server.id}) is not using the default security group."

            findings.append(report)

        return findings
