from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.compute.compute_client import compute_client


class compute_instance_isolated_private_network(Check):
    """Ensure compute instances are isolated in private networks without mixed public/private exposure."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for instance in compute_client.instances:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=instance)
            # Check if instance has private IPs
            has_private_ips = bool(instance.private_v4 or instance.private_v6)
            # Check if instance has public IPs
            has_public_ips = bool(
                instance.public_v4
                or instance.public_v6
                or instance.access_ipv4
                or instance.access_ipv6
            )

            # Instance is properly isolated if it has private IPs but no public IPs
            if has_private_ips and not has_public_ips:
                report.status = "PASS"
                private_ips = []
                if instance.private_v4:
                    private_ips.append(f"IPv4: {instance.private_v4}")
                if instance.private_v6:
                    private_ips.append(f"IPv6: {instance.private_v6}")
                ip_list = ", ".join(private_ips)
                report.status_extended = f"Instance {instance.name} ({instance.id}) is properly isolated in private network with private IPs ({ip_list}) and no public exposure."
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
