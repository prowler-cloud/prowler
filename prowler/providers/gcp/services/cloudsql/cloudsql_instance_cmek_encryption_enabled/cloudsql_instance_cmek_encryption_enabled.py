from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudsql.cloudsql_client import cloudsql_client


class cloudsql_instance_cmek_encryption_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in cloudsql_client.instances:
            report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
            if instance.cmek_key_name:
                report.status = "PASS"
                report.status_extended = (
                    f"Database instance {instance.name} is encrypted with "
                    f"customer-managed key: {instance.cmek_key_name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Database instance {instance.name} is not encrypted with a "
                    f"customer-managed key (CMEK); Google-managed key is in use."
                )
            findings.append(report)
        return findings
