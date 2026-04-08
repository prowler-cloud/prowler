from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elb.elb_client import elb_client
from prowler.providers.aws.services.cloudwatch.cloudwatch_client import cloudwatch_client


class elb_unhealthy_host_count_monitored(Check):
    def execute(self):
        findings = []
        metric_name = "UnHealthyHostCount"
        namespace = "AWS/ELB"
        
        # Iterate over all load balancers
        for lb_arn, lb in elb_client.loadbalancers.items():
            report = Check_Report_AWS(metadata=self.metadata(), resource=lb)
            report.resource_tags = lb.tags
            report.status = "FAIL"
            report.status_extended = f"Load Balancer {lb.name} does not have monitoring for unhealthy host count."

            # Check if there is a CloudWatch alarm for UnHealthyHostCount associated with this load balancer
            for alarm in cloudwatch_client.metric_alarms:
                if (
                    alarm.metric == metric_name
                    and alarm.name_space == namespace
                    and lb.name in alarm.resource_ids
                ):
                    report.status = "PASS"
                    report.status_extended = f"Load Balancer {lb.name} has monitoring for unhealthy host count."
                    break

            findings.append(report)

        return findings
