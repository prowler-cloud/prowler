from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.lightsail.lightsail_client import lightsail_client


class lightsail_static_ip_unused(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        for arn_static_ip, static_ip in lightsail_client.static_ips.items():
            report = Check_Report_AWS(self.metadata())
            report.region = static_ip.region
            report.resource_id = static_ip.id
            report.resource_arn = arn_static_ip
            report.resource_tags = []
            report.status = "FAIL"
            report.status_extended = (
                f"Static IP '{static_ip.name}' is not associated with any instance."
            )

            if static_ip.is_attached:
                report.status = "PASS"
                report.status_extended = f"Static IP '{static_ip.name}' is associated with the instance '{static_ip.attached_to}'."

            findings.append(report)

        return findings
