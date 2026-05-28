from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.instance.instance_client import instance_client


class instance_watchdog_enabled(Check):
    """Check if Linode instances have Watchdog (Lassie) enabled."""

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

            if instance.watchdog_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Instance '{instance.label}' has Watchdog (Lassie) enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Instance '{instance.label}' does not have Watchdog (Lassie) enabled."

            findings.append(report)

        return findings
