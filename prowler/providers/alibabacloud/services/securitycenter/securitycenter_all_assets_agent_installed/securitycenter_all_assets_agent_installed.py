from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.securitycenter.securitycenter_client import (
    securitycenter_client,
)


class securitycenter_all_assets_agent_installed(Check):
    """Check if all assets are installed with security agent."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        uninstalled_machines = securitycenter_client.uninstalled_machines

        if not uninstalled_machines:
            # All assets have the agent installed
            report = CheckReportAlibabaCloud(metadata=self.metadata(), resource={})
            report.region = securitycenter_client.region
            report.resource_id = securitycenter_client.audited_account
            report.resource_arn = (
                f"acs:sas::{securitycenter_client.audited_account}:security-center"
            )
            report.status = "PASS"
            report.status_extended = "All assets have Security Center agent installed."
            findings.append(report)
        else:
            # Report each uninstalled machine
            for machine in uninstalled_machines:
                report = CheckReportAlibabaCloud(
                    metadata=self.metadata(), resource=machine
                )
                report.region = machine.region
                report.resource_id = machine.instance_id
                report.resource_arn = (
                    f"acs:ecs:{machine.region}:{securitycenter_client.audited_account}:instance/{machine.instance_id}"
                    if machine.instance_id.startswith("i-")
                    or "ecs" in machine.instance_id.lower()
                    else f"acs:sas:{machine.region}:{securitycenter_client.audited_account}:machine/{machine.instance_id}"
                )
                report.status = "FAIL"
                report.status_extended = (
                    f"Asset {machine.instance_name if machine.instance_name else machine.instance_id} "
                    f"({machine.instance_id}) does not have Security Center agent installed. "
                    f"Region: {machine.region}, OS: {machine.os if machine.os else 'Unknown'}."
                )
                findings.append(report)

        return findings
