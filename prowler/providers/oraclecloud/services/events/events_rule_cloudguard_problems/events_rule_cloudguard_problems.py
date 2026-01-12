"""Check Ensure a notification is configured for Oracle Cloud Guard problems detected."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.cloudguard.cloudguard_client import (
    cloudguard_client,
)
from prowler.providers.oraclecloud.services.events.events_client import events_client
from prowler.providers.oraclecloud.services.events.lib.helpers import (
    check_event_rule_has_notification_actions,
    filter_rules_by_event_types,
)


class events_rule_cloudguard_problems(Check):
    """Check Ensure a notification is configured for Oracle Cloud Guard problems detected."""

    def execute(self) -> Check_Report_OCI:
        """Execute the events_rule_cloudguard_problems check."""
        findings = []

        # Required event types for Cloud Guard notifications
        required_event_types = [
            "com.oraclecloud.cloudguard.problemdetected",
            "com.oraclecloud.cloudguard.problemdismissed",
            "com.oraclecloud.cloudguard.problemremediated",
        ]

        # Get Cloud Guard reporting region (if Cloud Guard is configured)
        reporting_region = None
        if cloudguard_client.configuration:
            reporting_region = cloudguard_client.configuration.reporting_region

        # Filter rules that monitor Cloud Guard problems
        matching_rules = filter_rules_by_event_types(
            events_client.rules, required_event_types
        )

        # If reporting region is set, filter rules to only those in that region
        if reporting_region:
            matching_rules = [
                (rule, condition)
                for rule, condition in matching_rules
                if rule.region == reporting_region
            ]

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
                report.status_extended = f"Event rule '{rule.name}' is configured to monitor Cloud Guard problems with notifications."
                if reporting_region:
                    report.status_extended += (
                        f" (Cloud Guard reporting region: {reporting_region})"
                    )
            else:
                report.status = "FAIL"
                report.status_extended = f"Event rule '{rule.name}' monitors Cloud Guard problems but does not have notification actions configured."

            findings.append(report)

        # If no matching rules found, create a single FAIL finding
        if not findings:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource={},
                region=reporting_region if reporting_region else "global",
                resource_name="Cloud Guard Problem Notifications",
                resource_id=events_client.audited_tenancy,
                compartment_id=events_client.audited_tenancy,
            )
            report.status = "FAIL"
            region_note = (
                f" in Cloud Guard reporting region '{reporting_region}'"
                if reporting_region
                else ""
            )
            report.status_extended = f"No event rules configured{region_note} to monitor Cloud Guard problems (detected, dismissed, remediated)."
            findings.append(report)

        return findings
