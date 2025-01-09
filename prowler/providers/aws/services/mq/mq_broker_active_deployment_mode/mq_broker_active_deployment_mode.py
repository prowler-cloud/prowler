from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.mq.mq_client import mq_client
from prowler.providers.aws.services.mq.mq_service import DeploymentMode, EngineType


class mq_broker_active_deployment_mode(Check):
    def execute(self):
        findings = []
        for broker in mq_client.brokers.values():
            if broker.engine_type == EngineType.ACTIVEMQ:
                report = Check_Report_AWS(self.metadata())
                report.region = broker.region
                report.resource_id = broker.id
                report.resource_arn = broker.arn
                report.resource_tags = broker.tags
                report.status = "FAIL"
                report.status_extended = f"MQ Apache ActiveMQ Broker {broker.name} does not have an active/standby deployment mode."
                if broker.deployment_mode == DeploymentMode.ACTIVE_STANDBY_MULTI_AZ:
                    report.status = "PASS"
                    report.status_extended = f"MQ Apache ActiveMQ Broker {broker.name} does have an active/standby deployment mode."

                findings.append(report)

        return findings
