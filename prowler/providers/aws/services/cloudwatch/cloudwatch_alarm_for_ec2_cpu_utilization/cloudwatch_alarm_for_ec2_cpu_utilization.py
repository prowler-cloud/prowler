from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudwatch.cloudwatch_client import cloudwatch_client
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class cloudwatch_alarm_for_ec2_cpu_utilization(Check):
    def execute(self):
        findings = []

        # Define the expected metric name and namespace for EC2 CPU utilization
        expected_metric_name = 'CPUUtilization'
        expected_namespace = 'AWS/EC2'

        for instance in ec2_client.instances:
            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            report.resource_tags = instance.tags
            report.status = "FAIL"
            report.status_extended = f"No CloudWatch alarms found for EC2 instance '{instance.id}' CPU utilization."

            # Check if any alarm is configured for EC2 CPU utilization for the current instance
            alarms_found = any(
                alarm.metric == expected_metric_name and alarm.name_space == expected_namespace
                for alarm in cloudwatch_client.metric_alarms
            )

            if alarms_found:
                report.status = "PASS"
                report.status_extended = f"CloudWatch alarm(s) found for EC2 instance '{instance.id}' CPU utilization."

            findings.append(report)

        return findings
