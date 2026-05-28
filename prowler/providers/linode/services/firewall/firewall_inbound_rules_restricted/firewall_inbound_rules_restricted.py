from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.firewall.firewall_client import firewall_client

INTERNET_CIDRS = {"0.0.0.0/0", "::/0"}


def _rule_allows_all_from_internet(rule) -> bool:
    """Check if a rule allows all ports/protocols from the internet."""
    if rule.action != "ACCEPT":
        return False
    # All ports = empty ports string or "1-65535"
    all_ports = not rule.ports or rule.ports.strip() in ("", "1-65535")
    all_protocols = rule.protocol in ("ALL", "TCP", "UDP")

    if not (all_ports and all_protocols):
        return False

    all_addresses = rule.addresses_ipv4 + rule.addresses_ipv6
    for addr in all_addresses:
        if addr in INTERNET_CIDRS:
            return True
    return False


class firewall_inbound_rules_restricted(Check):
    """Check if Linode firewalls have restricted inbound rules."""

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

            permissive_rules = [
                rule
                for rule in fw.inbound_rules
                if _rule_allows_all_from_internet(rule)
            ]

            if permissive_rules:
                report.status = "FAIL"
                report.status_extended = (
                    f"Firewall '{fw.label}' has {len(permissive_rules)} overly permissive "
                    f"inbound rule(s) allowing all traffic from the internet."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Firewall '{fw.label}' does not have overly permissive inbound rules."

            findings.append(report)

        return findings
