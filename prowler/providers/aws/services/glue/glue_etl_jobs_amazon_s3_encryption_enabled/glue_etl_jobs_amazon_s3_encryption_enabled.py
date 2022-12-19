from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.glue.glue_client import glue_client


class glue_etl_jobs_amazon_s3_encryption_enabled(Check):
    def execute(self):
        findings = []
        for job in glue_client.jobs:
            no_sec_configs = True
            report = Check_Report_AWS(self.metadata())
            report.resource_id = job.name
            report.region = job.region
            for sec_config in glue_client.security_configs:
                if sec_config.name == job.security:
                    no_sec_configs = False
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Glue job {job.name} does not have S3 encryption enabled."
                    )
                    if sec_config.s3_encryption != "DISABLED":
                        report.status = "PASS"
                        report.status_extended = f"Glue job {job.name} has S3 encryption enabled with key {sec_config.s3_key_arn}."
            if no_sec_configs:
                if job.arguments and job.arguments.get("--encryption-type") == "sse-s3":
                    report.status = "PASS"
                    report.status_extended = (
                        f"Glue job {job.name} has S3 encryption enabled."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Glue job {job.name} does not have security configuration."
                    )
            findings.append(report)
        return findings
