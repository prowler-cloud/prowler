from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_instance_multiple_network_interfaces(Check):
    """
    Ensure that VM instances have a single network interface.

    This check evaluates whether Compute Engine instances are configured with only
    one network interface to minimize network complexity and reduce attack surface.
    - PASS: The VM instance has a single network interface, or is a GKE-managed instance
            (which may legitimately require multiple interfaces).
    - FAIL: The VM instance has multiple network interfaces (excluding GKE instances).
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []
        for instance in compute_client.instances:
            report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
            report.status = "PASS"
            report.status_extended = (
                f"VM Instance {instance.name} has a single network interface."
            )
            if instance.network_interfaces_count > 1:
                # GKE instances may legitimately require multiple network interfaces
                if instance.name.startswith("gke-"):
                    report.status = "PASS"
                    report.status_extended = f"VM Instance {instance.name} has {instance.network_interfaces_count} network interfaces. This is a GKE-managed instance which may legitimately require multiple interfaces. Manual review recommended."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"VM Instance {instance.name} has {instance.network_interfaces_count} network interfaces."
            findings.append(report)

        return findings
