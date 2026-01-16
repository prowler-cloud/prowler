import re

from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_instance_desired_machine_type(Check):
    """
    Ensure Compute Engine VM instances use approved machine types.

    This check evaluates whether each VM instance's machine type is included in
    the organization's approved list of machine types configured via
    `desired_machine_types` in the Prowler configuration file.

    - PASS: The VM instance uses an approved machine type.
    - FAIL: The VM instance uses a machine type not in the approved list.
    - MANUAL: GKE-managed instance requires manual review.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []

        desired_machine_types = compute_client.audit_config.get(
            "desired_machine_types", []
        )

        for instance in compute_client.instances:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=instance,
            )
            report.status = "PASS"

            # GKE instances - manual review
            if instance.name.startswith("gke-"):
                report.status = "MANUAL"
                report.status_extended = (
                    f"VM Instance {instance.name} is a GKE-managed node "
                    f"({instance.machine_type}). Manual review recommended."
                )
                findings.append(report)
                continue

            if not desired_machine_types:
                report.status_extended = (
                    f"VM Instance {instance.name} not evaluated - "
                    "no desired machine types configured."
                )
                findings.append(report)
                continue

            is_approved = False
            for pattern in desired_machine_types:
                if re.search(pattern, instance.machine_type):
                    is_approved = True
                    break

            if is_approved:
                report.status_extended = (
                    f"VM Instance {instance.name} uses approved machine type "
                    f"{instance.machine_type}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"VM Instance {instance.name} uses machine type "
                    f"{instance.machine_type}, which is not in the approved list."
                )

            findings.append(report)

        return findings
