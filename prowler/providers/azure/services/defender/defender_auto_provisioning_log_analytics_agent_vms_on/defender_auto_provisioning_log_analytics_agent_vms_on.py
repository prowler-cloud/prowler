from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_auto_provisioning_log_analytics_agent_vms_on(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            auto_provisioning_settings,
        ) in defender_client.auto_provisioning_settings.items():

            for auto_provisioning_setting in auto_provisioning_settings.values():

                report = Check_Report_Azure(self.metadata())
                report.status = "PASS"
                report.subscription = subscription_name
                report.resource_name = auto_provisioning_setting.resource_name
                report.resource_id = auto_provisioning_setting.resource_id
                report.status_extended = f"Defender Auto Provisioning Log Analytics Agents from subscription {subscription_name} is set to ON."

                if auto_provisioning_setting.auto_provision != "On":
                    report.status = "FAIL"
                    report.status_extended = f"Defender Auto Provisioning Log Analytics Agents from subscription {subscription_name} is set to OFF."

                findings.append(report)

        return findings
