"""Check Create at least one notification topic and subscription to receive monitoring alerts."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.events.events_client import events_client


class events_notification_topic_and_subscription_exists(Check):
    """Check Create at least one notification topic and subscription to receive monitoring alerts."""

    def execute(self) -> Check_Report_OCI:
        """Execute the events_notification_topic_and_subscription_exists check."""
        findings = []

        # Check if at least one topic with subscriptions exists
        has_topic_with_subscription = any(
            len(topic.subscriptions) > 0 for topic in events_client.topics
        )

        # Create a single report for tenancy-level check
        # Use the first topic's region if available, otherwise use the first audited region
        region = "global"
        if events_client.topics:
            region = events_client.topics[0].region
        elif events_client.audited_regions:
            # audited_regions contains OCIRegion objects, extract the key
            first_region = events_client.audited_regions[0]
            region = (
                first_region.key if hasattr(first_region, "key") else str(first_region)
            )

        report = Check_Report_OCI(
            metadata=self.metadata(),
            resource={},
            region=region,
            resource_name="Notification Service",
            resource_id=events_client.audited_tenancy,
            compartment_id=events_client.audited_tenancy,
        )

        if has_topic_with_subscription:
            report.status = "PASS"
            report.status_extended = (
                "At least one notification topic with active subscriptions exists."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                "No notification topics with active subscriptions found."
            )

        findings.append(report)

        return findings
