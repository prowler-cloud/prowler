from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_instance_deletion_protection_enabled(Check):
    """
    Ensure that VM instance has deletion protection enabled.

    This check verifies whether GCP Compute Engine VM instances have deletion protection
    enabled to prevent accidental termination of production or critical workloads.

    - PASS: VM instance has deletion protection enabled.
    - FAIL: VM instance does not have deletion protection enabled.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []
        for instance in compute_client.instances:
            report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
            report.status = "PASS"
            report.status_extended = (
                f"VM Instance {instance.name} has deletion protection enabled."
            )
            if not instance.deletion_protection:
                report.status = "FAIL"
                report.status_extended = f"VM Instance {instance.name} does not have deletion protection enabled."
            findings.append(report)

        return findings
