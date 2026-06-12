from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.firewall.firewall_client import firewall_client


class firewall_status_enabled(Check):
    """Check if Linode Cloud Firewalls are enabled."""

    def execute(self) -> list[CheckReportLinode]:
        findings = []

        for fw in firewall_client.firewalls:
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
