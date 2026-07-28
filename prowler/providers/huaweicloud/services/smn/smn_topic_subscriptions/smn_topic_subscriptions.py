from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.smn.smn_client import smn_client


class smn_topic_subscriptions(Check):
    """Check if SMN topics have at least one subscription configured."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []
        if not smn_client.topics:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource={},
            )
            report.region = smn_client.region
            report.resource_id = smn_client.audited_account
            report.resource_name = "SMN Topics"
            report.resource_arn = f"huaweicloud:smn:{smn_client.region}:{smn_client.audited_account}:topics"
            report.status = "FAIL"
            report.status_extended = "No SMN topics are configured. Notifications cannot be delivered without topics."
            findings.append(report)
            return findings

        for topic in smn_client.topics:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource=topic,
            )
            report.region = topic.region
            report.resource_id = topic.topic_id
            report.resource_name = topic.name
            report.resource_arn = f"huaweicloud:smn:{topic.region}:{smn_client.audited_account}:topic/{topic.topic_id}"

            if topic.subscription_count > 0:
                report.status = "PASS"
                report.status_extended = f"SMN topic '{topic.name}' ({topic.topic_id}) has {topic.subscription_count} subscription(s) configured."
            else:
                report.status = "FAIL"
                report.status_extended = f"SMN topic '{topic.name}' ({topic.topic_id}) has no subscriptions. Notifications will not be delivered."

            findings.append(report)

        return findings
