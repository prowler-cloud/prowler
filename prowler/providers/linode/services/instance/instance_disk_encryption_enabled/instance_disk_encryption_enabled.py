from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.instance.instance_client import instance_client


class instance_disk_encryption_enabled(Check):
    """Check if Linode instances have disk encryption enabled."""

    def execute(self) -> list[CheckReportLinode]:
        """Execute the instance_disk_encryption_enabled check.

        Iterates over all Linode instances and checks whether disk encryption
        is enabled.

        Returns:
            list[CheckReportLinode]: A list of findings for each instance.
        """
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

            if instance.disk_encryption == "enabled":
                report.status = "PASS"
                report.status_extended = (
                    f"Instance '{instance.label}' has disk encryption enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Instance '{instance.label}' does not have disk encryption enabled."

            findings.append(report)

        return findings
