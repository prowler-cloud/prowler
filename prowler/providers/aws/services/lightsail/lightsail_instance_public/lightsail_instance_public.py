from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.lightsail.lightsail_client import lightsail_client


class lightsail_instance_public(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        for arn_instance, instance in lightsail_client.instances.items():
            report = Check_Report_AWS(self.metadata())
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = arn_instance
            report.resource_tags = instance.tags
            report.status = "PASS"
            report.status_extended = (
                f"Instance '{instance.name}' is not publicly exposed."
            )

            open_public_ports = [
                port for port in instance.ports if port.access_type == "public"
            ]

            if instance.public_ip != "" and len(open_public_ports) > 0:
                report.status = "FAIL"
                report.status_extended = f"Instance '{instance.name}' is publicly exposed. The open ports are: {', '.join(open_port.range for open_port in open_public_ports)}"

            findings.append(report)

        return findings
