"""Check Ensure Oracle Integration Cloud (OIC) access is restricted to allowed sources."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.integration.integration_client import (
    integration_client,
)


class integration_instance_access_restricted(Check):
    """Check Ensure Oracle Integration Cloud (OIC) access is restricted to allowed sources."""

    def execute(self) -> Check_Report_OCI:
        """Execute the integration_instance_access_restricted check."""
        findings = []

        for instance in integration_client.integration_instances:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=instance,
                region=instance.region,
                resource_name=instance.display_name,
                resource_id=instance.id,
                compartment_id=instance.compartment_id,
            )
            # Check if instance has no network endpoint details (unrestricted access)
            if not instance.network_endpoint_details:
                report.status = "FAIL"
                report.status_extended = f"Integration instance {instance.display_name} has no network endpoint details configured (unrestricted access)."
            # Check if 0.0.0.0/0 is in network endpoint details
            elif "0.0.0.0/0" in str(instance.network_endpoint_details):
                report.status = "FAIL"
                report.status_extended = f"Integration instance {instance.display_name} has unrestricted access with 0.0.0.0/0 in network endpoint details."
            # Check if PUBLIC endpoint with no allowlists
            elif (
                instance.network_endpoint_details.get("network_endpoint_type")
                == "PUBLIC"
                and not instance.network_endpoint_details.get("allowlisted_http_ips")
                and not instance.network_endpoint_details.get("allowlisted_http_vcns")
            ):
                report.status = "FAIL"
                report.status_extended = f"Integration instance {instance.display_name} has public access with no IP or VCN allowlists configured."
            else:
                report.status = "PASS"
                report.status_extended = f"Integration instance {instance.display_name} has restricted network access configured."

            findings.append(report)

        return findings
