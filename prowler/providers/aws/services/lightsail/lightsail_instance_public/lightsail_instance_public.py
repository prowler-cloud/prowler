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
            report.status = "FAIL"
            report.status_extended = f"Instance '{instance.name}' has public access"
            if instance.public_ip == "" and not any(
                port.access_type == "public" for port in instance.ports
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"Instance '{instance.name}' has no public access"
                )

            findings.append(report)

        return findings
