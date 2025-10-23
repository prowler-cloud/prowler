"""Check Ensure a notification is configured for VCN changes."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.events.events_client import events_client
from prowler.providers.oraclecloud.services.events.lib.helpers import (
    check_event_rule_has_notification_actions,
    filter_rules_by_event_types,
)


class events_rule_vcn_changes(Check):
    """Check Ensure a notification is configured for VCN changes."""

    def execute(self) -> Check_Report_OCI:
        """Execute the events_rule_vcn_changes check."""
        findings = []

        # Required event types for VCN changes
        required_event_types = [
            "com.oraclecloud.virtualnetwork.createvcn",
            "com.oraclecloud.virtualnetwork.deletevcn",
            "com.oraclecloud.virtualnetwork.updatevcn",
        ]

        # Filter rules that monitor VCN changes
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
                report.status_extended = f"Event rule '{rule.name}' is configured to monitor VCN changes with notifications."
            else:
                report.status = "FAIL"
                report.status_extended = f"Event rule '{rule.name}' monitors VCN changes but does not have notification actions configured."

            findings.append(report)

        # If no matching rules found, create a single FAIL finding
        if not findings:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource={},
                region="global",
                resource_name="Vcn Changes Event Rule",
                resource_id=events_client.audited_tenancy,
                compartment_id=events_client.audited_tenancy,
            )
            report.status = "FAIL"
            report.status_extended = "No event rules configured to monitor VCN changes."
            findings.append(report)

        return findings
