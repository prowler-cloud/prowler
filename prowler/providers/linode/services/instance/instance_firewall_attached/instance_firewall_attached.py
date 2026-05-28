from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.instance.instance_client import instance_client


class instance_firewall_attached(Check):
    """Check if Linode instances with public IPs have a firewall attached."""

    def execute(self) -> list[CheckReportLinode]:
        findings = []

        for instance in instance_client.instances:
            # Only evaluate instances that have public IP addresses
            if not instance.ipv4_public:
                continue

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
                    f"Instance '{instance.label}' has a public IP and "
                    f"{instance.firewalls_count} firewall(s) attached."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Instance '{instance.label}' has a public IP "
                    f"({', '.join(instance.ipv4_public)}) but no firewall attached."
                )

            findings.append(report)

        return findings
