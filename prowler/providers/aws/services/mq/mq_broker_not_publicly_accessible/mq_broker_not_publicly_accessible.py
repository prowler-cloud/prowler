from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.mq.mq_client import mq_client


class mq_broker_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for broker in mq_client.brokers.values():
            report = Check_Report_AWS(self.metadata())
            report.region = broker.region
            report.resource_id = broker.id
            report.resource_arn = broker.arn
            report.resource_tags = broker.tags
            report.status = "FAIL"
            report.status_extended = f"MQ Broker {broker.name} is publicly accessible."

            if not broker.publicly_accessible:
                report.status = "PASS"
                report.status_extended = (
                    f"MQ Broker {broker.name} is not publicly accessible."
                )

            findings.append(report)

        return findings
