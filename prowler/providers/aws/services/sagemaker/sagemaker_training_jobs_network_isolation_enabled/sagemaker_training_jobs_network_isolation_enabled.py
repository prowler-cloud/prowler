from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_training_jobs_network_isolation_enabled(Check):
    def execute(self):
        findings = []
        for training_job in sagemaker_client.sagemaker_training_jobs:
            report = Check_Report_AWS(self.metadata())
            report.region = training_job.region
            report.resource_id = training_job.name
            report.resource_arn = training_job.arn
            report.status = "PASS"
            report.status_extended = f"Sagemaker training job {training_job.name} has network isolation enabled"
            if not training_job.network_isolation:
                report.status = "FAIL"
                report.status_extended = f"Sagemaker training job {training_job.name} has network isolation disabled"

            findings.append(report)

        return findings
