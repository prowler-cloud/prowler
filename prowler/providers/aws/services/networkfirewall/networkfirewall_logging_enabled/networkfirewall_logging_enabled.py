from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudwatch.cloudwatch_client import (
    cloudwatch_client,
)
from prowler.providers.aws.services.kinesis.kinesis_client import kinesis_client
from prowler.providers.aws.services.networkfirewall.networkfirewall_client import (
    networkfirewall_client,
)
from prowler.providers.aws.services.networkfirewall.networkfirewall_service import (
    LogDestinationType,
    LogType,
)
from prowler.providers.aws.services.s3.s3_client import s3_client


class networkfirewall_logging_enabled(Check):
    def execute(self):
        findings = []
        for arn, firewall in networkfirewall_client.network_firewalls.items():
            report = Check_Report_AWS(self.metadata())
            report.region = firewall.region
            report.resource_id = firewall.name
            report.resource_arn = arn
            report.resource_tags = firewall.tags
            report.status = "FAIL"
            report.status_extended = f"Network Firewall {firewall.name} does not have logging enabled in any destination."

            for configuration in firewall.logging_configuration:
                destination_exists = False
                if configuration.log_type in LogType:
                    if configuration.log_destination_type == LogDestinationType.s3:
                        destination_exists = s3_client._head_bucket(
                            configuration.log_destination
                        )
                    elif (
                        configuration.log_destination_type
                        == LogDestinationType.cloudwatch_logs
                    ):
                        destination_exists = cloudwatch_client.des(
                            configuration.log_destination
                        )
                    elif (
                        configuration.log_destination_type
                        == LogDestinationType.kinesis_data_firehose
                    ):
                        destination_exists = kinesis_client.describe_stream(
                            configuration.log_destination
                        )

                    if destination_exists:
                        report.status = "PASS"
                        report.status_extended = f"Network Firewall {firewall.name} has logging enabled in at least one destination."
                        break

            findings.append(report)

        return findings
