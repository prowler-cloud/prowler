from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.firewall.firewall_client import firewall_client


class firewall_outbound_rules_configured(Check):
    """Check if Linode Cloud Firewall has outbound rules configured."""

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

            if len(fw.outbound_rules) == 0:
                report.status = "FAIL"
                report.status_extended = (
                    f"Firewall '{fw.label}' has no outbound rules configured."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Firewall '{fw.label}' has {len(fw.outbound_rules)} outbound rule(s) configured."

            findings.append(report)

        return findings
