from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.glue.glue_client import glue_client


class glue_etl_jobs_cloudwatch_logs_encryption_enabled(Check):
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
                    report.status_extended = f"Glue job {job.name} does not have CloudWatch Logs encryption enabled."
                    if sec_config.cw_encryption != "DISABLED":
                        report.status = "PASS"
                        report.status_extended = f"Glue job {job.name} has CloudWatch Logs encryption enabled with key {sec_config.cw_key_arn}."
            if no_sec_configs:
                report.status = "FAIL"
                report.status_extended = (
                    f"Glue job {job.name} does not have security configuration."
                )
            findings.append(report)
        return findings
