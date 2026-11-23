from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client


class network_application_gateway_waf_enabled(Check):
    """Application Gateway has an enabled Web Application Firewall policy associated."""

    def execute(self) -> list[Check_Report_Azure]:
        """Evaluate the WAF policy association of every Application Gateway.

        Returns:
            One finding per Application Gateway, plus one MANUAL finding for
            each subscription whose gateways, or whose WAF policies with a
            gateway's policy state unknown, could not be listed or read
            completely. A gateway covered by that finding gets none of its
            own. Any other gateway whose policy state cannot be determined is
            MANUAL.
        """
        findings = []
        for subscription_id, gateways in network_client.application_gateways.items():
            subscription_name = network_client.subscriptions.get(
                subscription_id, subscription_id
            )
            gateways_unlisted = (
                subscription_id in network_client.application_gateways_lookup_failed
            )
            # A policy state left unknown by a failed listing or read is reported
            # once for the subscription; a missing policy keeps its own finding.
            policies_unlisted = (
                subscription_id in network_client.waf_policies_lookup_failed
            )
            unknown_policy_state = {
                gateway.id
                for gateway in gateways.values()
                if gateway.firewall_policy_id
                and gateway.firewall_policy_enabled is None
                and (
                    policies_unlisted
                    or gateway.firewall_policy_id.casefold()
                    in network_client.waf_policy_reads_failed
                )
            }
            policies_unreadable = bool(unknown_policy_state)
            if gateways_unlisted or policies_unreadable:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription_id
                report.resource_name = subscription_id
                report.resource_id = f"/subscriptions/{subscription_id}"
                report.status = "MANUAL"
                scope = f"Cannot evaluate the WAF policy association of the Application Gateways in subscription {subscription_name} ({subscription_id})"
                if gateways_unlisted and policies_unreadable:
                    report.status_extended = f"{scope}: they could not be listed completely, and the WAF policies associated with them could not be listed or read completely. Check the scan log for the errors, and verify that Microsoft.Network/applicationGateways/read and Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/read (both included in Reader) are granted to the scanning identity."
                elif gateways_unlisted:
                    report.status_extended = f"{scope}: they could not be listed completely. Check the scan log for the error, and verify that Microsoft.Network/applicationGateways/read (included in Reader) is granted to the scanning identity."
                else:
                    report.status_extended = f"{scope}: the WAF policies associated with them could not be listed or read completely. Check the scan log for the error, and verify that Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/read (included in Reader) is granted to the scanning identity."
                findings.append(report)
            for gateway in gateways.values():
                if policies_unreadable and gateway.id in unknown_policy_state:
                    continue
                report = Check_Report_Azure(metadata=self.metadata(), resource=gateway)
                report.subscription = subscription_id
                prefix = f"Application Gateway {gateway.name} in subscription {subscription_name} ({subscription_id})"
                if gateway.firewall_policy_id:
                    if gateway.firewall_policy_enabled:
                        report.status = "PASS"
                        report.status_extended = (
                            f"{prefix} has an enabled WAF policy associated."
                        )
                    elif gateway.firewall_policy_enabled is False:
                        report.status = "FAIL"
                        report.status_extended = f"{prefix} has a WAF policy associated, but the policy is disabled."
                    else:
                        report.status = "MANUAL"
                        report.status_extended = f"{prefix} has a WAF policy associated, but the state of that policy could not be determined. Check the scan log for the error."
                elif gateway.waf_configuration_enabled:
                    report.status = "FAIL"
                    report.status_extended = f"{prefix} uses the legacy WAF configuration instead of a WAF policy."
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"{prefix} has no gateway-level WAF policy associated."
                    )
                findings.append(report)
        return findings
