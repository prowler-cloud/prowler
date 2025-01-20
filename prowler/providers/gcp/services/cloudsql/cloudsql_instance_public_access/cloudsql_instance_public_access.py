from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudsql.cloudsql_client import cloudsql_client


class cloudsql_instance_public_access(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in cloudsql_client.instances:
            report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
            report.status = "PASS"
            report.status_extended = f"Database Instance {instance.name} does not whitelist all Public IP Addresses."
            for network in instance.authorized_networks:
                if network["value"] == "0.0.0.0/0":
                    report.status = "FAIL"
                    report.status_extended = f"Database Instance {instance.name} whitelist all Public IP Addresses."
            findings.append(report)

        return findings
