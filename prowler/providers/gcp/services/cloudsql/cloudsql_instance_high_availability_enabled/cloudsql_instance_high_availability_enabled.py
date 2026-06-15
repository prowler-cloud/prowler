from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudsql.cloudsql_client import cloudsql_client


class cloudsql_instance_high_availability_enabled(Check):
    """Check that Cloud SQL primary instances are configured for high availability.

    Verifies that each Cloud SQL primary instance has `availabilityType` set to
    `REGIONAL`, which provisions a standby replica in a different zone within
    the same region and enables automatic failover on zone-level outages. Read
    replicas are skipped because they inherit availability from their primary.
    """

    def execute(self) -> list[Check_Report_GCP]:
        """Execute the high availability check across all Cloud SQL instances.

        Returns:
            A list of `Check_Report_GCP` findings, one per Cloud SQL primary
            instance. Status is `PASS` when `availability_type == "REGIONAL"`
            and `FAIL` otherwise.
        """
        findings = []
        for instance in cloudsql_client.instances:
            if instance.instance_type != "CLOUD_SQL_INSTANCE":
                continue
            report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
            if instance.availability_type == "REGIONAL":
                report.status = "PASS"
                report.status_extended = (
                    f"Database instance {instance.name} has high availability "
                    f"(REGIONAL) configured."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Database instance {instance.name} does not have high "
                    f"availability configured (current: "
                    f"{instance.availability_type})."
                )
            findings.append(report)
        return findings
