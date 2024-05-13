from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.lightsail.lightsail_client import lightsail_client


class lightsail_instance_no_public_ip(Check):
    def execute(self):
        findings = []
        for arn_instance, instance in lightsail_client.instances.items():
            report = Check_Report_AWS(self.metadata())
            report.region = instance.location.get("regionName", "")
            report.resource_id = instance.id
            report.resource_arn = arn_instance
            report.resource_tags = instance.tags
            report.status = "PASS"
            report.status_extended = (
                f"Instance '{instance.name}' does not have a public IP."
            )
            if instance.public_ip != "":
                report.status = "FAIL"
                report.status_extended = f"Instance '{instance.name}' has a public IP."

            findings.append(report)

        return findings
