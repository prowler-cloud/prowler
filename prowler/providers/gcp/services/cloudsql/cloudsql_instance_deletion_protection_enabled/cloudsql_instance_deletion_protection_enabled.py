from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudsql.cloudsql_client import cloudsql_client

AUDITED_INSTANCE_TYPES = ("CLOUD_SQL_INSTANCE", "READ_REPLICA_INSTANCE")


class cloudsql_instance_deletion_protection_enabled(Check):
    """Cloud SQL instance has deletion protection enabled.

    Primary instances and read replicas are evaluated, because a read replica
    does not inherit the setting from its primary. Other instance types, such
    as read pools and on-premises source representations, are skipped because
    Cloud SQL documents deletion protection only for instances and replicas.
    """

    def execute(self) -> list[Check_Report_GCP]:
        """Evaluate deletion protection on every Cloud SQL instance and replica.

        Returns:
            One finding per primary instance or read replica.
        """
        findings = []
        for instance in cloudsql_client.instances:
            if instance.instance_type not in AUDITED_INSTANCE_TYPES:
                continue
            report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
            if instance.deletion_protection_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Database instance {instance.name} has deletion protection "
                    "enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Database instance {instance.name} does not have deletion "
                    "protection enabled."
                )
            findings.append(report)
        return findings
