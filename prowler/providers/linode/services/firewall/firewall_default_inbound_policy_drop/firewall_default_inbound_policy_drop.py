from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.firewall.firewall_client import firewall_client


class firewall_default_inbound_policy_drop(Check):
    """Check if Linode Cloud Firewall default inbound policy is DROP."""

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

            if fw.inbound_policy == "DROP":
                report.status = "PASS"
                report.status_extended = (
                    f"Firewall '{fw.label}' has default inbound policy set to DROP."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Firewall '{fw.label}' has default inbound policy set to {fw.inbound_policy}."

            findings.append(report)

        return findings
