from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_auto_provisioning_log_analytics_agent_vms_on(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription, auto_provisioning_settings in defender_client.auto_provisioning_settings.items():
            report = Check_Report_Azure(self.metadata())
            report.status = "PASS"
            report.subscription = subscription
            report.resource_name = "Defender Auto Provisioning Log Analytics Agents On"
            report.resource_id = auto_provisioning_settings["default"].resource_id
            report.status_extended = f"Defenter Auto Provisioning Log Analytics Agents from subscription {subscription} is set to ON."

            for ap in auto_provisioning_settings:
                if auto_provisioning_settings[ap].auto_provision != "On":
                    report.status = "FAIL"
                    report.status_extended = f"Defenter Auto Provisioning Log Analytics Agents from subscription {subscription} is set to OFF."

            findings.append(report)

        return findings
