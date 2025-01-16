from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elb.elb_client import elb_client


class elb_connection_draining_enabled(Check):
    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        for lb in elb_client.loadbalancers.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource_metadata=lb)
            report.status = "PASS"
            report.status_extended = f"ELB {lb.name} has connection draining enabled."

            if not lb.connection_draining:
                report.status = "FAIL"
                report.status_extended = (
                    f"ELB {lb.name} does not have connection draining enabled."
                )

            findings.append(report)

        return findings
