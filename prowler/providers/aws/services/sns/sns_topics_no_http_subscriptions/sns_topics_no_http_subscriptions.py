from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sns.sns_client import sns_client


class sns_topics_no_http_subscriptions(Check):
    def execute(self):
        findings = []
        for topic in sns_client.topics:
            for subscription in topic.subscriptions:
                if subscription.arn == "PendingConfirmation":
                    continue
                report = Check_Report_AWS(self.metadata())
                report.region = topic.region
                report.resource_id = topic.name
                report.resource_arn = topic.arn
                report.resource_tags = topic.tags
                report.status = "PASS"
                report.status_extended = (
                    f"Subscription {subscription.arn} is using an HTTPS endpoint."
                )

                if subscription.protocol == "http":
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Subscription {subscription.arn} is using an HTTP endpoint."
                    )

                findings.append(report)

        return findings
