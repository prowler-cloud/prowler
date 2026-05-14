from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_instance_suspended_without_persistent_disks(Check):
    """
    Ensure that VM instances in SUSPENDED state do not have persistent disks attached.

    This check identifies VM instances that are in a SUSPENDED or SUSPENDING state
    and have persistent disks still attached. Suspended VMs with attached disks
    represent unused infrastructure that continues to incur storage costs.

    - PASS: VM instance is not in SUSPENDED/SUSPENDING state, or is suspended but has no disks attached.
    - FAIL: VM instance is in SUSPENDED/SUSPENDING state with persistent disks attached.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []
        for instance in compute_client.instances:
            report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
            report.status = "PASS"
            report.status_extended = f"VM Instance {instance.name} is not suspended."

            if instance.status in ("SUSPENDED", "SUSPENDING"):
                attached_disks = [disk.name for disk in instance.disks]

                if attached_disks:
                    report.status = "FAIL"
                    report.status_extended = f"VM Instance {instance.name} is {instance.status.lower()} with {len(attached_disks)} persistent disk(s) attached: {', '.join(attached_disks)}."
                else:
                    report.status_extended = f"VM Instance {instance.name} is {instance.status.lower()} but has no persistent disks attached."

            findings.append(report)

        return findings
