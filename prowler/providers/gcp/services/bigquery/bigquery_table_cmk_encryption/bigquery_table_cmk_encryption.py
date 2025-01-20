from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.bigquery.bigquery_client import bigquery_client


class bigquery_table_cmk_encryption(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for table in bigquery_client.tables:
            report = Check_Report_GCP(metadata=self.metadata(), resource=table)
            report.status = "PASS"
            report.status_extended = (
                f"Table {table.name} is encrypted with Customer-Managed Keys (CMKs)."
            )
            if not table.cmk_encryption:
                report.status = "FAIL"
                report.status_extended = f"Table {table.name} is not encrypted with Customer-Managed Keys (CMKs)."
            findings.append(report)

        return findings
