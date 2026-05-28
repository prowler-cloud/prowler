from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.firewall.firewall_client import firewall_client

INTERNET_CIDRS = {"0.0.0.0/0", "::/0"}


def _rule_allows_rdp_from_internet(rule) -> bool:
    """Check if a rule allows RDP (port 3389) from the internet."""
    if rule.action != "ACCEPT":
        return False
    if rule.protocol not in ("TCP", "ALL"):
        return False
    # Check if port 3389 is included
    if rule.ports:
        ports_str = rule.ports.strip()
        if ports_str == "3389":
            pass
        elif "-" in ports_str:
            try:
                start, end = ports_str.split("-", 1)
                if not (int(start) <= 3389 <= int(end)):
                    return False
            except ValueError:
                return False
        elif "," in ports_str:
            if "3389" not in [p.strip() for p in ports_str.split(",")]:
                return False
        else:
            # Single port that isn't 3389
            try:
                if int(ports_str) != 3389:
                    return False
            except ValueError:
                return False
    # Empty ports means all ports

    # Check if source is internet
    all_addresses = rule.addresses_ipv4 + rule.addresses_ipv6
    for addr in all_addresses:
        if addr in INTERNET_CIDRS:
            return True
    return False


class firewall_blocks_rdp_from_internet(Check):
    """Check if Linode firewalls block RDP (port 3389) from the internet."""

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

            rdp_open = any(
                _rule_allows_rdp_from_internet(rule) for rule in fw.inbound_rules
            )

            if rdp_open:
                report.status = "FAIL"
                report.status_extended = (
                    f"Firewall '{fw.label}' allows RDP (port 3389) from the internet."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Firewall '{fw.label}' does not allow RDP from the internet."
                )

            findings.append(report)

        return findings
