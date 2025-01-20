from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.bigquery.bigquery_client import bigquery_client


class bigquery_dataset_public_access(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for dataset in bigquery_client.datasets:
            report = Check_Report_GCP(metadata=self.metadata(), resource=dataset)
            report.status = "PASS"
            report.status_extended = (
                f"Dataset {dataset.name} is not publicly accessible."
            )
            if dataset.public:
                report.status = "FAIL"
                report.status_extended = (
                    f"Dataset {dataset.name} is publicly accessible."
                )
            findings.append(report)

        return findings
