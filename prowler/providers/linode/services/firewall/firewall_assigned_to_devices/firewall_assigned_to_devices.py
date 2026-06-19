from prowler.lib.check.models import Check, CheckReportLinode
from prowler.lib.logger import logger
from prowler.providers.linode.services.firewall.firewall_client import firewall_client


class firewall_assigned_to_devices(Check):
    """Check if Linode Cloud Firewalls are assigned to at least one device."""

    def execute(self) -> list[CheckReportLinode]:
        """Execute the firewall_assigned_to_devices check.

        Iterates over all Cloud Firewalls and checks whether each one is
        assigned to at least one device.

        Returns:
            list[CheckReportLinode]: A list of findings for each firewall.
        """
        findings = []

        for fw in firewall_client.firewalls:
            # When the device count could not be determined (the devices fetch
            # failed) skip the firewall instead of reporting a false FAIL.
            if fw.attached_devices_count is None:
                logger.warning(
                    f"firewall - Skipping firewall '{fw.label}' ({fw.id}): "
                    "device assignment could not be determined."
                )
                continue

            report = CheckReportLinode(
                metadata=self.metadata(),
                resource=fw,
                resource_name=fw.label,
                resource_id=str(fw.id),
                region="global",
            )
            report.resource_tags = fw.tags

            if fw.attached_devices_count > 0:
                report.status = "PASS"
                report.status_extended = f"Firewall '{fw.label}' is assigned to {fw.attached_devices_count} device(s)."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Firewall '{fw.label}' is not assigned to any device."
                )

            findings.append(report)

        return findings
