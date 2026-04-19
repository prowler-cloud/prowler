from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aks.aks_client import aks_client


class aks_cluster_defender_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_name, clusters in aks_client.clusters.items():
            for cluster_id, cluster in clusters.items():
                resource = cluster
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=resource
                )
                report.subscription = subscription_name
                report.resource_name = resource.name
                report.resource_id = resource.id
                report.location = resource.location

                if resource.defender_enabled:
                    report.status = "PASS"
                    report.status_extended = (
                        f"{resource.name} has Defender for Containers enabled."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"{resource.name} does not have Defender for Containers enabled."
                    )

                findings.append(report)

        return findings
