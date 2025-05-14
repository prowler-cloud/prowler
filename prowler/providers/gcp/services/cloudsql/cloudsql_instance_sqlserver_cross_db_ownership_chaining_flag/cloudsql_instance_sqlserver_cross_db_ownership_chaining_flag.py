from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudsql.cloudsql_client import cloudsql_client


class cloudsql_instance_sqlserver_cross_db_ownership_chaining_flag(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in cloudsql_client.instances:
            if "SQLSERVER" in instance.version:
                report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
                report.status = "PASS"
                report.status_extended = f"SQL Server Instance {instance.name} has 'cross db ownership chaining' flag set to 'off'."
                for flag in instance.flags:
                    if (
                        flag.get("name", "") == "cross db ownership chaining"
                        and flag.get("value", "off") == "on"
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"SQL Server Instance {instance.name} does not have 'cross db ownership chaining' flag set to 'off'."
                        break
                findings.append(report)

        return findings
