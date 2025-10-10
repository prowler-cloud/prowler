"""Check if Secure Boot is enabled on Compute Instance."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.compute.compute_client import compute_client


class compute_instance_secure_boot_enabled(Check):
    """Check if Secure Boot is enabled on Compute Instance."""

    def execute(self) -> Check_Report_OCI:
        """Execute the compute_instance_secure_boot_enabled check.

        Returns:
            List of Check_Report_OCI objects with findings
        """
        findings = []

        for instance in compute_client.instances:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=instance,
                region=instance.region,
                resource_name=instance.name,
                resource_id=instance.id,
                compartment_id=instance.compartment_id,
            )

            if instance.is_secure_boot_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Compute instance {instance.name} has Secure Boot enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Compute instance {instance.name} does not have Secure Boot enabled."

            findings.append(report)

        return findings
