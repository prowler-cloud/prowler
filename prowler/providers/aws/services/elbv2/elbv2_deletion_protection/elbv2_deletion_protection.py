from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class elbv2_deletion_protection(Check):
    def execute(self):
        findings = []
        for lb in elbv2_client.loadbalancersv2.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=lb)
            report.status = "FAIL"
            report.status_extended = (
                f"ELBv2 {lb.name} does not have deletion protection enabled."
            )
            if lb.deletion_protection == "true":
                report.status = "PASS"
                report.status_extended = (
                    f"ELBv2 {lb.name} has deletion protection enabled."
                )

            findings.append(report)

        return findings
