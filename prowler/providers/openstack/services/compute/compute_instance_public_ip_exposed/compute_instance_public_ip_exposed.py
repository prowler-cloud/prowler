from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.compute.compute_client import compute_client
from prowler.providers.openstack.services.compute.lib.ip import is_public_ip


class compute_instance_public_ip_exposed(Check):
    """Ensure compute instances are not exposed to the internet via public IP addresses."""

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

            # Check networks for any additional public IPs (beyond first one captured in SDK attributes)
            # This handles cases where instances have multiple public IPs on different networks
            sdk_ips = {
                instance.public_v4,
                instance.public_v6,
                instance.access_ipv4,
                instance.access_ipv6,
            }
            for network_name, ip_list in instance.networks.items():
                for ip in ip_list:
                    # Check if IP is public and not already captured in SDK attributes
                    if is_public_ip(ip) and ip not in sdk_ips:
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
