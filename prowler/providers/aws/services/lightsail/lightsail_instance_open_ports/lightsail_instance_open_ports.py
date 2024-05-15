from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.lightsail.lightsail_client import lightsail_client


class lightsail_instance_open_ports(Check):
    def execute(self):
        findings = []
        for arn_instance, instance in lightsail_client.instances.items():
            report = Check_Report_AWS(self.metadata())
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = arn_instance
            report.resource_tags = instance.tags
            report.status = "PASS"
            report.status_extended = (
                f"Instance '{instance.name}' does not have open unnecesary ports."
            )
            opened_ports = []
            for port in instance.ports:
                if port.range not in ["80", "443"]:
                    opened_ports.append(port.range)

            if opened_ports:
                report.status = "FAIL"
                report.status_extended = f"Instance '{instance.name}' has open ports: {', '.join(opened_ports)}."

            findings.append(report)

        return findings
