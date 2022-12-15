from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_elastic_ip_unassgined(Check):
    def execute(self):
        findings = []
        for eip in ec2_client.elastic_ips:
            report = Check_Report_AWS(self.metadata())
            report.region = eip.region
            if eip.public_ip:
                report.resource_id = eip.public_ip
                report.status = "FAIL"
                report.status_extended = f"Elastic IP {eip.public_ip} is not associated with an instance or network interface."
                if eip.association_id:
                    report.status = "PASS"
                    report.status_extended = f"Elastic IP {eip.public_ip} is associated with an instance or network interface."
                findings.append(report)

        return findings
