from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.instance.instance_client import instance_client


class instance_without_firewall(Check):
    """Check if Linode instances have a firewall attached."""

    def execute(self) -> list[CheckReportLinode]:
        findings = []

        for instance in instance_client.instances:
            report = CheckReportLinode(
                metadata=self.metadata(),
                resource=instance,
                resource_name=instance.label,
                resource_id=str(instance.id),
                region=instance.region,
            )
            report.resource_tags = instance.tags

            if instance.firewalls_count > 0:
                report.status = "PASS"
                report.status_extended = (
                    f"Instance '{instance.label}' has {instance.firewalls_count} "
                    f"firewall(s) attached."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Instance '{instance.label}' does not have any firewall attached."
                )

            findings.append(report)

        return findings
