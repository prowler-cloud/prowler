from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client


class network_bastion_host_exists(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, bastion_hosts in network_client.bastion_hosts.items():
            if not bastion_hosts:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription
                report.resource_name = subscription
                report.resource_id = (
                    f"/subscriptions/{network_client.subscriptions[subscription]}"
                )
                report.status = "FAIL"
                report.status_extended = (
                    f"Bastion Host from subscription {subscription} does not exist"
                )
                findings.append(report)
            else:
                for bastion_host in bastion_hosts:
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=bastion_host
                    )
                    report.subscription = subscription
                    report.status = "PASS"
                    report.status_extended = f"Bastion Host {bastion_host.name} exists in subscription {subscription}."
                    findings.append(report)

        return findings
