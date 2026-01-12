"""Check if In-transit Encryption is enabled on Compute Instance."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.compute.compute_client import compute_client


class compute_instance_in_transit_encryption_enabled(Check):
    """Check if In-transit Encryption is enabled on Compute Instance."""

    def execute(self) -> Check_Report_OCI:
        """Execute the compute_instance_in_transit_encryption_enabled check.

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

            # In-transit encryption is enabled when is_pv_encryption_in_transit_enabled is True
            if instance.is_pv_encryption_in_transit_enabled:
                report.status = "PASS"
                report.status_extended = f"Compute instance {instance.name} has in-transit encryption enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"Compute instance {instance.name} does not have in-transit encryption enabled."

            findings.append(report)

        return findings
