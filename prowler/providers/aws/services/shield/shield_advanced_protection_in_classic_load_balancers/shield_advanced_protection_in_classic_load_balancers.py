from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elb.elb_client import elb_client
from prowler.providers.aws.services.shield.shield_client import shield_client


class shield_advanced_protection_in_classic_load_balancers(Check):
    def execute(self):
        findings = []
        if shield_client.enabled:
            for lb in elb_client.loadbalancers.values():
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource_metadata=lb
                )
                report.region = shield_client.region
                report.status = "FAIL"
                report.status_extended = (
                    f"ELB {lb.name} is not protected by AWS Shield Advanced."
                )

                for protection in shield_client.protections.values():
                    if lb.arn == protection.resource_arn:
                        report.status = "PASS"
                        report.status_extended = (
                            f"ELB {lb.name} is protected by AWS Shield Advanced."
                        )
                        break

                findings.append(report)

        return findings
