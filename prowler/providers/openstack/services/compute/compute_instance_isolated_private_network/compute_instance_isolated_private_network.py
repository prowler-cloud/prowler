from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.compute.compute_client import compute_client
from prowler.providers.openstack.services.compute.lib.ip import is_public_ip


class compute_instance_isolated_private_network(Check):
    """Ensure compute instances are isolated in private networks without mixed public/private exposure."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for instance in compute_client.instances:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=instance)

            private_ip_list = []
            public_ip_list = []

            # Classify IPs from networks dict using actual IP validation
            for ip_list in instance.networks.values():
                for ip in ip_list:
                    if is_public_ip(ip):
                        public_ip_list.append(ip)
                    else:
                        private_ip_list.append(ip)

            # Also check SDK fields for IPs not present in networks
            seen_ips = set(private_ip_list + public_ip_list)
            for ip in [
                instance.public_v4,
                instance.public_v6,
                instance.access_ipv4,
                instance.access_ipv6,
            ]:
                if ip and ip not in seen_ips and is_public_ip(ip):
                    public_ip_list.append(ip)
            for ip in [instance.private_v4, instance.private_v6]:
                if ip and ip not in seen_ips and not is_public_ip(ip):
                    private_ip_list.append(ip)

            has_private_ips = bool(private_ip_list)
            has_public_ips = bool(public_ip_list)

            # Determine status based on IP classification
            if has_private_ips and not has_public_ips:
                report.status = "PASS"
                ip_display = ", ".join(private_ip_list)
                report.status_extended = f"Instance {instance.name} ({instance.id}) is properly isolated in private network with private IPs ({ip_display}) and no public exposure."
            elif has_public_ips and has_private_ips:
                report.status = "FAIL"
                report.status_extended = f"Instance {instance.name} ({instance.id}) has mixed public and private network exposure (not properly isolated)."
            elif has_public_ips and not has_private_ips:
                report.status = "FAIL"
                report.status_extended = f"Instance {instance.name} ({instance.id}) has only public IP addresses (no private network isolation)."
            else:
                # No IPs at all (edge case)
                report.status = "FAIL"
                report.status_extended = f"Instance {instance.name} ({instance.id}) has no network configuration (no IPs assigned)."

            findings.append(report)

        return findings
