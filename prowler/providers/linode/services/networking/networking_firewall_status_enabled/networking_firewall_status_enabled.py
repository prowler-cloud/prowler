from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.networking.networking_client import (
    networking_client,
)


class networking_firewall_status_enabled(Check):
    """Check if Linode Cloud Firewalls are enabled."""

    def execute(self) -> list[CheckReportLinode]:
        """Execute the networking_firewall_status_enabled check.

        Iterates over all Cloud Firewalls and checks whether each one has
        an enabled status.

        Returns:
            list[CheckReportLinode]: A list of findings for each firewall.
        """
        findings = []

        for fw in networking_client.firewalls:
            report = CheckReportLinode(
                metadata=self.metadata(),
                resource=fw,
                resource_name=fw.label,
                resource_id=str(fw.id),
                region="global",
            )
            report.resource_tags = fw.tags

            if fw.status == "enabled":
                report.status = "PASS"
                report.status_extended = f"Firewall '{fw.label}' is enabled."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Firewall '{fw.label}' is not enabled (status: {fw.status})."
                )

            findings.append(report)

        return findings
