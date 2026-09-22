from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.smn.smn_client import smn_client


class smn_topic_subscriptions(Check):
    """Check if SMN topics have at least one subscription configured."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for topic in smn_client.topics:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource=topic,
            )
            report.region = topic.region
            report.resource_id = topic.topic_id
            report.resource_name = topic.name
            report.resource_arn = topic.topic_urn

            if topic.confirmed_subscription_count > 0:
                report.status = "PASS"
                report.status_extended = (
                    f"SMN topic '{topic.name}' ({topic.topic_id}) has "
                    f"{topic.confirmed_subscription_count} confirmed subscription(s)."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"SMN topic '{topic.name}' ({topic.topic_id}) has no confirmed "
                    "subscriptions. Notifications will not be delivered."
                )

            findings.append(report)

        return findings
