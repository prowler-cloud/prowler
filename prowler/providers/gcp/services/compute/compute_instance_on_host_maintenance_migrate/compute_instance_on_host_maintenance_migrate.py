from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_instance_on_host_maintenance_migrate(Check):
    """
    Ensure Compute Engine VM instances have On Host Maintenance set to MIGRATE.

    This check evaluates whether VM instances are configured to live migrate during
    host maintenance events, preventing downtime when Google performs maintenance.

    - PASS: VM instance has On Host Maintenance set to MIGRATE.
    - FAIL: VM instance has On Host Maintenance set to TERMINATE.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []
        for instance in compute_client.instances:
            report = Check_Report_GCP(metadata=self.metadata(), resource=instance)

            if instance.on_host_maintenance == "MIGRATE":
                report.status = "PASS"
                report.status_extended = f"VM Instance {instance.name} has On Host Maintenance set to MIGRATE."
            else:
                report.status = "FAIL"
                if instance.preemptible or instance.provisioning_model == "SPOT":
                    vm_type = "preemptible" if instance.preemptible else "Spot"
                    report.status_extended = (
                        f"VM Instance {instance.name} is a {vm_type} VM and has On Host Maintenance set to TERMINATE. "
                        f"{vm_type.capitalize()} VMs cannot use MIGRATE and must always use TERMINATE. "
                        f"If high availability is required, consider using a non-preemptible VM instead."
                    )
                else:
                    report.status_extended = (
                        f"VM Instance {instance.name} has On Host Maintenance set to "
                        f"{instance.on_host_maintenance} instead of MIGRATE."
                    )

            findings.append(report)

        return findings
