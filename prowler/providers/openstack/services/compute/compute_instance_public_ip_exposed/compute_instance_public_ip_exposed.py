import ipaddress
from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.compute.compute_client import compute_client


class compute_instance_public_ip_exposed(Check):
    """Ensure compute instances are not exposed to the internet via public IP addresses."""

    def _is_public_ip(self, ip_str: str) -> bool:
        """Check if an IP address is public (not private/RFC1918)."""
        try:
            ip = ipaddress.ip_address(ip_str)
            # Check if IP is not in private ranges
            return not (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
            )
        except ValueError:
            return False

    def _is_external_network(self, network_name: str) -> bool:
        """Detect if network name indicates external/public network."""
        external_patterns = [
            "ext",
            "external",
            "public",
            "internet",
            "wan",
            "floating",
        ]
        network_lower = network_name.lower()
        return any(pattern in network_lower for pattern in external_patterns)

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for instance in compute_client.instances:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=instance)
            # Collect all potential public IP indicators
            public_ips = []
            # Check SDK computed properties
            if instance.public_v4:
                public_ips.append(f"Public IPv4: {instance.public_v4}")
            if instance.public_v6:
                public_ips.append(f"Public IPv6: {instance.public_v6}")
            if instance.access_ipv4:
                public_ips.append(f"Access IPv4: {instance.access_ipv4}")
            if instance.access_ipv6:
                public_ips.append(f"Access IPv6: {instance.access_ipv6}")

            # Check networks for external attachments and public IPs
            for network_name, ip_list in instance.networks.items():
                # Check if network name suggests external/public network
                if self._is_external_network(network_name):
                    for ip in ip_list:
                        if self._is_public_ip(ip):
                            public_ips.append(
                                f"{network_name} network: {ip} (public range)"
                            )

            # Remove duplicates while preserving order
            seen = set()
            unique_public_ips = []
            for ip in public_ips:
                if ip not in seen:
                    seen.add(ip)
                    unique_public_ips.append(ip)

            if not unique_public_ips:
                report.status = "PASS"
                report.status_extended = f"Instance {instance.name} ({instance.id}) is not exposed to the internet (no public IP addresses or external network attachments detected)."
            else:
                report.status = "FAIL"
                ip_list = ", ".join(unique_public_ips)
                report.status_extended = f"Instance {instance.name} ({instance.id}) is exposed to the internet with public IP addresses: {ip_list}."

            findings.append(report)

        return findings
