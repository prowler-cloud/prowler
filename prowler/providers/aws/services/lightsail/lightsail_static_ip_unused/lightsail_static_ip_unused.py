from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.lightsail.lightsail_client import lightsail_client


class lightsail_static_ip_unused(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        for static_ip in lightsail_client.static_ips.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=static_ip)
            report.status = "FAIL"
            report.status_extended = (
                f"Static IP '{static_ip.name}' is not associated with any instance."
            )

            if static_ip.is_attached:
                report.status = "PASS"
                report.status_extended = f"Static IP '{static_ip.name}' is associated with the instance '{static_ip.attached_to}'."

            findings.append(report)

        return findings
