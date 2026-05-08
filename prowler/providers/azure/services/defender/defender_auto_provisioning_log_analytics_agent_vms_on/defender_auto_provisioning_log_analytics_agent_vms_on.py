from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_auto_provisioning_log_analytics_agent_vms_on(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        if defender_client.resource_groups:
            for subscription in defender_client.subscriptions:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription
                report.resource_name = "Not Applicable"
                report.resource_id = "Not Applicable"
                report.status = "MANUAL"
                report.status_extended = f"Subscription '{subscription}': this check is subscription-scoped and cannot be evaluated when --azure-resource-group is active. Re-run without --azure-resource-group to get full results."
                findings.append(report)
            return findings

        for (
            subscription_id,
            auto_provisioning_settings,
        ) in defender_client.auto_provisioning_settings.items():
            subscription_name = defender_client.subscriptions.get(
                subscription_id, subscription_id
            )
            for auto_provisioning_setting in auto_provisioning_settings.values():
                report = Check_Report_Azure(
                    metadata=self.metadata(),
                    resource=auto_provisioning_setting,
                )
                report.subscription = subscription_id
                report.status = "PASS"
                report.status_extended = f"Defender Auto Provisioning Log Analytics Agents from subscription {subscription_name} ({subscription_id}) is set to ON."

                if auto_provisioning_setting.auto_provision != "On":
                    report.status = "FAIL"
                    report.status_extended = f"Defender Auto Provisioning Log Analytics Agents from subscription {subscription_name} ({subscription_id}) is set to OFF."

                findings.append(report)

        return findings
