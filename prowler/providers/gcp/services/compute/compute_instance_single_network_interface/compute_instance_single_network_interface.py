from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_instance_single_network_interface(Check):
    """
    Ensure that VM instances have a single network interface.

    This check evaluates whether Compute Engine instances are configured with only
    one network interface to minimize network complexity and reduce attack surface.
    - PASS: The VM instance has a single network interface.
    - MANUAL: The VM instance is a GKE-managed instance with multiple network interfaces
              (manual review recommended as these may legitimately require multiple interfaces).
    - FAIL: The VM instance has multiple network interfaces (excluding GKE instances).
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []
        for instance in compute_client.instances:
            report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
            report.status = "PASS"

            interface_names = [nic.name for nic in instance.network_interfaces]
            interface_count = len(instance.network_interfaces)

            if interface_count == 1:
                report.status_extended = f"VM Instance {instance.name} has a single network interface: {interface_names[0]}."
            elif interface_count > 1:
                # GKE instances may legitimately require multiple network interfaces
                if instance.name.startswith("gke-"):
                    report.status = "MANUAL"
                    report.status_extended = f"VM Instance {instance.name} has {interface_count} network interfaces: {', '.join(interface_names)}. This is a GKE-managed instance which may legitimately require multiple interfaces. Manual review recommended."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"VM Instance {instance.name} has {interface_count} network interfaces: {', '.join(interface_names)}."
            else:
                report.status_extended = (
                    f"VM Instance {instance.name} has no network interfaces."
                )

            findings.append(report)

        return findings
