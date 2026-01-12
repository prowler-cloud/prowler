"""Check Ensure a notification is configured for network gateway changes."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.events.events_client import events_client
from prowler.providers.oraclecloud.services.events.lib.helpers import (
    check_event_rule_has_notification_actions,
    filter_rules_by_event_types,
)


class events_rule_network_gateway_changes(Check):
    """Check Ensure a notification is configured for network gateway changes."""

    def execute(self) -> Check_Report_OCI:
        """Execute the events_rule_network_gateway_changes check."""
        findings = []

        # Required event types for network gateway changes
        required_event_types = [
            "com.oraclecloud.virtualnetwork.createdrg",
            "com.oraclecloud.virtualnetwork.deletedrg",
            "com.oraclecloud.virtualnetwork.updatedrg",
            "com.oraclecloud.virtualnetwork.createdrgattachment",
            "com.oraclecloud.virtualnetwork.deletedrgattachment",
            "com.oraclecloud.virtualnetwork.updatedrgattachment",
            "com.oraclecloud.virtualnetwork.changeinternetgatewaycompartment",
            "com.oraclecloud.virtualnetwork.createinternetgateway",
            "com.oraclecloud.virtualnetwork.deleteinternetgateway",
            "com.oraclecloud.virtualnetwork.updateinternetgateway",
            "com.oraclecloud.virtualnetwork.changelocalpeeringgatewaycompartment",
            "com.oraclecloud.virtualnetwork.createlocalpeeringgateway",
            "com.oraclecloud.virtualnetwork.deletelocalpeeringgateway.end",
            "com.oraclecloud.virtualnetwork.updatelocalpeeringgateway",
            "com.oraclecloud.natgateway.changenatgatewaycompartment",
            "com.oraclecloud.natgateway.createnatgateway",
            "com.oraclecloud.natgateway.deletenatgateway",
            "com.oraclecloud.natgateway.updatenatgateway",
            "com.oraclecloud.servicegateway.attachserviceid",
            "com.oraclecloud.servicegateway.changeservicegatewaycompartment",
            "com.oraclecloud.servicegateway.createservicegateway",
            "com.oraclecloud.servicegateway.deleteservicegateway.end",
            "com.oraclecloud.servicegateway.detachserviceid",
            "com.oraclecloud.servicegateway.updateservicegateway",
        ]

        # Filter rules that monitor network gateway changes
        matching_rules = filter_rules_by_event_types(
            events_client.rules, required_event_types
        )

        # Create findings for each matching rule
        for rule, _ in matching_rules:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=rule,
                region=rule.region,
                resource_name=rule.name,
                resource_id=rule.id,
                compartment_id=rule.compartment_id,
            )

            # Check if the rule has notification actions
            if check_event_rule_has_notification_actions(rule):
                report.status = "PASS"
                report.status_extended = f"Event rule '{rule.name}' is configured to monitor network gateway changes with notifications."
            else:
                report.status = "FAIL"
                report.status_extended = f"Event rule '{rule.name}' monitors network gateway changes but does not have notification actions configured."

            findings.append(report)

        # If no matching rules found, create a single FAIL finding
        if not findings:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource={},
                region="global",
                resource_name="Network Gateway Changes Event Rule",
                resource_id=events_client.audited_tenancy,
                compartment_id=events_client.audited_tenancy,
            )
            report.status = "FAIL"
            report.status_extended = (
                "No event rules configured to monitor network gateway changes."
            )
            findings.append(report)

        return findings
