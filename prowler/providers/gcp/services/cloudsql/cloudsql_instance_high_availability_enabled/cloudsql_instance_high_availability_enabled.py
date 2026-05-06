from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudsql.cloudsql_client import cloudsql_client


class cloudsql_instance_high_availability_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in cloudsql_client.instances:
            report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
            if instance.high_availability:
                report.status = "PASS"
                report.status_extended = (
                    f"Database instance {instance.name} has high availability "
                    f"(REGIONAL) configured."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Database instance {instance.name} does not have high "
                    f"availability configured (availabilityType is ZONAL)."
                )
            findings.append(report)
        return findings
