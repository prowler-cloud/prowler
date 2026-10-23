from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.elb.elb_client import elb_client


class elb_load_balancer_configured(Check):
    """Check if at least one ELB load balancer is configured."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        if elb_client.load_balancers:
            for load_balancer in elb_client.load_balancers:
                report = CheckReportHuaweiCloud(
                    metadata=self.metadata(), resource=load_balancer
                )
                report.region = load_balancer.region
                report.resource_id = load_balancer.id
                report.resource_arn = (
                    f"huaweicloud:elb:{load_balancer.region}:"
                    f"{elb_client.audited_account}:loadbalancer/{load_balancer.id}"
                )
                report.status = "PASS"
                report.status_extended = (
                    f"ELB load balancer {load_balancer.name} ({load_balancer.id}) "
                    f"is configured."
                )
                findings.append(report)
        else:
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource={})
            report.region = elb_client.region
            report.resource_id = "no-load-balancer"
            report.resource_name = "load-balancer"
            report.resource_arn = ""
            report.status = "FAIL"
            report.status_extended = "No ELB load balancers are configured."
            findings.append(report)

        return findings
