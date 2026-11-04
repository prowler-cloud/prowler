from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client


class network_application_gateway_http2_enabled(Check):
    """Application Gateway has HTTP/2 enabled for client connections."""

    def execute(self) -> list[Check_Report_Azure]:
        """Evaluate the HTTP/2 setting of every Application Gateway.

        Returns:
            One finding per Application Gateway, plus one MANUAL finding for
            each subscription whose gateways could not be listed completely.
        """
        findings = []
        for subscription_id, gateways in network_client.application_gateways.items():
            subscription_name = network_client.subscriptions.get(
                subscription_id, subscription_id
            )
            if subscription_id in network_client.application_gateways_lookup_failed:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription_id
                report.resource_name = subscription_id
                report.resource_id = f"/subscriptions/{subscription_id}"
                report.status = "MANUAL"
                report.status_extended = f"Cannot evaluate HTTP/2 on the Application Gateways in subscription {subscription_name} ({subscription_id}): they could not be listed completely. Check the scan log for the error, and verify that Microsoft.Network/applicationGateways/read (included in Reader) is granted to the scanning identity."
                findings.append(report)
            for gateway in gateways.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=gateway)
                report.subscription = subscription_id
                prefix = f"Application Gateway {gateway.name} in subscription {subscription_name} ({subscription_id})"
                if gateway.http2_enabled:
                    report.status = "PASS"
                    report.status_extended = f"{prefix} has HTTP/2 enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"{prefix} does not have HTTP/2 enabled."
                findings.append(report)
        return findings
