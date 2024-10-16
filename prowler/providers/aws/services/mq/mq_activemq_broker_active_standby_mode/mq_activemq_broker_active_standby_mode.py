from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.mq.mq_client import mq_client
from prowler.providers.aws.services.mq.mq_service import DeploymentMode, EngineType


class mq_activemq_broker_active_standby_mode(Check):
    def execute(self):
        findings = []
        for broker in mq_client.brokers.values():
            report = Check_Report_AWS(self.metadata())
            report.region = broker.region
            report.resource_id = broker.id
            report.resource_arn = broker.arn
            report.resource_tags = broker.tags
            report.status = "FAIL"
            report.status_extended = f"MQ Broker {broker.id} does not have active/standby deployment mode enabled."

            if broker.engine_type == EngineType.ACTIVEMQ:
                if broker.deployment_mode == DeploymentMode.ACTIVE_STANDBY_MULTI_AZ:
                    report.status = "PASS"
                    report.status_extended = f"MQ Broker {broker.id} does have active/standby deployment mode enabled."

                findings.append(report)

        return findings
