from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.elb.elb_client import elb_client


class elb_public_exposure(Check):
    """Check if ELB load balancers have public IP addresses exposed."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for load_balancer in elb_client.load_balancers:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(), resource=load_balancer
            )
            report.region = load_balancer.region
            report.resource_id = load_balancer.id
            report.resource_arn = (
                f"huaweicloud:elb:{load_balancer.region}:{elb_client.audited_account}:loadbalancer/{load_balancer.id}"
            )

            if load_balancer.is_public:
                report.status = "FAIL"
                report.status_extended = (
                    f"ELB load balancer {load_balancer.name} ({load_balancer.id}) "
                    f"has a public IP address {load_balancer.public_ip}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"ELB load balancer {load_balancer.name} ({load_balancer.id}) "
                    f"does not have a public IP address."
                )

            findings.append(report)

        return findings
