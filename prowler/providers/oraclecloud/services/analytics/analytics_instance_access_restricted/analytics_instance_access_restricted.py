"""Check Ensure Oracle Analytics Cloud (OAC) access is restricted to allowed sources or deployed within a Virtual Cloud Network."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.analytics.analytics_client import (
    analytics_client,
)


class analytics_instance_access_restricted(Check):
    """Check Ensure Oracle Analytics Cloud (OAC) access is restricted to allowed sources or deployed within a Virtual Cloud Network."""

    def execute(self) -> Check_Report_OCI:
        """Execute the analytics_instance_access_restricted check."""
        findings = []

        for instance in analytics_client.analytics_instances:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=instance,
                region=instance.region,
                resource_name=instance.name,
                resource_id=instance.id,
                compartment_id=instance.compartment_id,
            )

            # Check if instance has PUBLIC network endpoint type
            if (
                instance.network_endpoint_type
                and instance.network_endpoint_type.upper() == "PUBLIC"
            ):
                # Check if whitelisted IPs are configured
                if not instance.whitelisted_ips:
                    report.status = "FAIL"
                    report.status_extended = f"Analytics instance {instance.name} has public access with no whitelisted IPs configured."
                # Check if 0.0.0.0/0 is in whitelisted IPs
                elif "0.0.0.0/0" in instance.whitelisted_ips:
                    report.status = "FAIL"
                    report.status_extended = f"Analytics instance {instance.name} has public access with unrestricted IP range (0.0.0.0/0)."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Analytics instance {instance.name} has public access with restricted whitelisted IPs."
            else:
                report.status = "PASS"
                report.status_extended = f"Analytics instance {instance.name} is deployed within a VCN or has restricted access."

            findings.append(report)

        return findings
