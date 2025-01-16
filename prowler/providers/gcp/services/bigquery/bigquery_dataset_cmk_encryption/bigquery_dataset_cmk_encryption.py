from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.bigquery.bigquery_client import bigquery_client


class bigquery_dataset_cmk_encryption(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for dataset in bigquery_client.datasets:
            report = Check_Report_GCP(
                metadata=self.metadata(), resource_metadata=dataset
            )
            report.status = "PASS"
            report.status_extended = f"Dataset {dataset.name} is encrypted with Customer-Managed Keys (CMKs)."
            if not dataset.cmk_encryption:
                report.status = "FAIL"
                report.status_extended = f"Dataset {dataset.name} is not encrypted with Customer-Managed Keys (CMKs)."
            findings.append(report)

        return findings
