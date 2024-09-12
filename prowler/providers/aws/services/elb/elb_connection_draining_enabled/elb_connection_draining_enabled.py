from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elb.elb_client import elb_client


class elb_connection_draining_enabled(Check):
    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        for loadbalancer_arn, load_balancer in elb_client.loadbalancers.items():
            report = Check_Report_AWS(self.metadata())
            report.region = load_balancer.region
            report.resource_id = load_balancer.name
            report.resource_arn = loadbalancer_arn
            report.resource_tags = load_balancer.tags
            report.status = "PASS"
            report.status_extended = f"Connection draining is enabled for Classic Load Balancer {load_balancer.name}."

            if not load_balancer.connection_draining:
                report.status = "FAIL"
                report.status_extended = f"Connection draining is not enabled for Classic Load Balancer {load_balancer.name}."

            findings.append(report)

        return findings
