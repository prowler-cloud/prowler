from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sns.sns_client import sns_client


class sns_subscription_not_using_http_endpoints(Check):
    def execute(self):
        findings = []
        for topic in sns_client.topics:
            for subscription in topic.subscriptions:
                if subscription.arn == "PendingConfirmation":
                    continue
                report = Check_Report_AWS(self.metadata())
                report.region = topic.region
                report.resource_id = subscription.id
                report.resource_arn = subscription.arn
                report.resource_tags = topic.tags
                report.resource_details = topic.arn
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
