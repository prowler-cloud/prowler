from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.shield.shield_client import shield_client


class shield_advanced_protection_in_associated_elastic_ips(Check):
    def execute(self):
        findings = []
        if shield_client.enabled:
            for elastic_ip in ec2_client.elastic_ips:
                report = Check_Report_AWS(self.metadata())
                report.region = shield_client.region
                report.resource_id = elastic_ip.allocation_id
                report.resource_arn = elastic_ip.arn
                report.status = "FAIL"
                report.status_extended = f"Elastic IP {elastic_ip.allocation_id} is not protected by AWS Shield Advanced"

                for protection in shield_client.protections.values():
                    if elastic_ip.arn == protection.resource_arn:
                        report.status = "PASS"
                        report.status_extended = f"Elastic IP {elastic_ip.allocation_id} is protected by AWS Shield Advanced"
                        break

                findings.append(report)

        return findings
