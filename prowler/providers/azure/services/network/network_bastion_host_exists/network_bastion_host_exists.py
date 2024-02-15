from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client


class network_bastion_host_exists(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, bastion_hosts in network_client.bastion_hosts.items():
            if bastion_hosts == []:
                status = "FAIL"
                status_extended = (
                    f"Bastion Host from subscription {subscription} does not exist"
                )
            else:
                status = "PASS"
                status_extended = (
                    f"Bastion Host from subscription {subscription} exists"
                )

            report = Check_Report_Azure(self.metadata())
            report.subscription = subscription
            report.resource_name = "Bastion Host"
            report.resource_id = "N/A"
            report.status = status
            report.status_extended = status_extended
            findings.append(report)

        return findings
