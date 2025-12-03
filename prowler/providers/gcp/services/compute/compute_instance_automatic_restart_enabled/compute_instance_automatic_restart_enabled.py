from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_instance_automatic_restart_enabled(Check):
    """
    Ensure Compute Engine VM instances have Automatic Restart enabled.

    Reports PASS if a VM instance has automatic restart enabled, otherwise FAIL.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []
        for instance in compute_client.instances:
            report = Check_Report_GCP(metadata=self.metadata(), resource=instance)

            # Preemptible and Spot VMs cannot have automatic restart enabled
            if instance.preemptible or instance.provisioning_model == "SPOT":
                report.status = "FAIL"
                report.status_extended = (
                    f"VM Instance {instance.name} is a Preemptible or Spot instance, "
                    "which cannot have Automatic Restart enabled by design."
                )
            elif instance.automatic_restart:
                report.status = "PASS"
                report.status_extended = (
                    f"VM Instance {instance.name} has Automatic Restart enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"VM Instance {instance.name} does not have Automatic Restart enabled."

            findings.append(report)

        return findings
