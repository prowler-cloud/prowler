from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.mq.mq_client import mq_client


class mq_broker_auto_minor_version_upgrades(Check):
    def execute(self):
        findings = []
        for broker in mq_client.brokers.values():
            report = Check_Report_AWS(self.metadata())
            report.region = broker.region
            report.resource_id = broker.id
            report.resource_arn = broker.arn
            report.resource_tags = broker.tags
            report.status = "PASS"
            report.status_extended = f"MQ Broker {broker.name} does have automated minor version upgrades enabled."

            if not broker.auto_minor_version_upgrade:
                report.status = "FAIL"
                report.status_extended = f"MQ Broker {broker.name} does not have automated minor version upgrades enabled."

            findings.append(report)

        return findings
