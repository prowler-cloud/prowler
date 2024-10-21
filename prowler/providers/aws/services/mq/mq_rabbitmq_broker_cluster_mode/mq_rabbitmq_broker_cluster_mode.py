from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.mq.mq_client import mq_client
from prowler.providers.aws.services.mq.mq_service import DeploymentMode, EngineType


class mq_rabbitmq_broker_cluster_mode(Check):
    """Ensure MQ RabbitMQ Broker has cluster deployment mode enabled.

    This check will fail if the RabbitMQ Broker does not have cluster deployment mode enabled.
    """

    def execute(self) -> List[Check_Report_AWS]:
        """Execute the check.

        Returns:
            List[Check_Report_AWS]: A list of reports for each RabbitMQ Broker that does not have cluster deployment mode enabled.
        """
        findings = []
        for broker in mq_client.brokers.values():
            report = Check_Report_AWS(self.metadata())
            report.region = broker.region
            report.resource_id = broker.id
            report.resource_arn = broker.arn
            report.resource_tags = broker.tags
            report.status = "FAIL"
            report.status_extended = f"MQ RabbitMQ Broker {broker.name} does not have cluster deployment mode enabled."

            if broker.engine_type == EngineType.RABBITMQ:
                if broker.deployment_mode == DeploymentMode.CLUSTER_MULTI_AZ:
                    report.status = "PASS"
                    report.status_extended = f"MQ RabbitMQ Broker {broker.name} does have cluster deployment mode enabled."

                findings.append(report)

        return findings
