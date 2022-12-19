from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elb.elb_client import elb_client
from prowler.providers.aws.services.shield.shield_client import shield_client


class shield_advanced_protection_in_classic_load_balancers(Check):
    def execute(self):
        findings = []
        if shield_client.enabled:
            for elb in elb_client.loadbalancers:
                report = Check_Report_AWS(self.metadata())
                report.region = shield_client.region
                report.resource_id = elb.name
                report.resource_arn = elb.arn
                report.status = "FAIL"
                report.status_extended = (
                    f"ELB {elb.name} is not protected by AWS Shield Advanced"
                )

                for protection in shield_client.protections.values():
                    if elb.arn == protection.resource_arn:
                        report.status = "PASS"
                        report.status_extended = (
                            f"ELB {elb.name} is protected by AWS Shield Advanced"
                        )
                        break

                findings.append(report)

        return findings
