from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.lightsail.lightsail_client import lightsail_client


class lightsail_instance_no_public_ip(Check):
    def execute(self):
        findings = []
        for instance in lightsail_client.instances:
            report = Check_Report_AWS(self.metadata())
            report.region = instance.location.get("regionName", "")
            report.resource_id = instance.id
            report.resource_arn = instance.arn
            report.resource_tags = instance.tags
            report.status = "PASS"
            report.status_extended = (
                f"Instance {instance.id} does not have a public IP."
            )
            if instance.public_ip != "":
                report.status = "FAIL"
                report.status_extended = f"Instance {instance.id} has a public IP."

            findings.append(report)

        return findings
