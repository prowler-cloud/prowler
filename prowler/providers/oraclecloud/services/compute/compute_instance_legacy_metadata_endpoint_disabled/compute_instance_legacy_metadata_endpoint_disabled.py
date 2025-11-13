"""Check if Compute Instance Legacy Metadata service endpoint is disabled."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.compute.compute_client import compute_client


class compute_instance_legacy_metadata_endpoint_disabled(Check):
    """Check if Compute Instance Legacy Metadata service endpoint is disabled."""

    def execute(self) -> Check_Report_OCI:
        """Execute the compute_instance_legacy_metadata_endpoint_disabled check.

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

            if instance.are_legacy_imds_endpoints_disabled:
                report.status = "PASS"
                report.status_extended = f"Compute instance {instance.name} has legacy metadata service endpoint disabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"Compute instance {instance.name} has legacy metadata service endpoint enabled or not configured."

            findings.append(report)

        return findings
