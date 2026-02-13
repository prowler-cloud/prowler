from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_instance_preemptible_vm_disabled(Check):
    """
    Ensure GCP Compute Engine VM instances are not preemptible or Spot VMs.

    - PASS: VM instance is not preemptible (preemptible=False) and not Spot
      (provisioningModel != "SPOT").
    - FAIL: VM instance is preemptible (preemptible=True) or Spot
      (provisioningModel="SPOT").
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []
        for instance in compute_client.instances:
            report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
            report.status = "PASS"
            report.status_extended = (
                f"VM Instance {instance.name} is not preemptible or Spot VM."
            )

            if instance.preemptible or instance.provisioning_model == "SPOT":
                report.status = "FAIL"
                vm_type = "preemptible" if instance.preemptible else "Spot VM"
                report.status_extended = (
                    f"VM Instance {instance.name} is configured as {vm_type}."
                )

            findings.append(report)
        return findings
