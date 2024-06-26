from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.glue.glue_client import glue_client


class glue_development_endpoints_job_bookmark_encryption_enabled(Check):
    def execute(self):
        findings = []
        for endpoint in glue_client.dev_endpoints:
            no_sec_configs = True
            report = Check_Report_AWS(self.metadata())
            report.resource_id = endpoint.name
            report.resource_arn = endpoint.arn
            report.region = endpoint.region
            for sec_config in glue_client.security_configs:
                if sec_config.name == endpoint.security:
                    no_sec_configs = False
                    report.status = "FAIL"
                    report.status_extended = f"Glue development endpoint {endpoint.name} does not have Job Bookmark encryption enabled."
                    if sec_config.jb_encryption != "DISABLED":
                        report.status = "PASS"
                        report.status_extended = f"Glue development endpoint {endpoint.name} has Job Bookmark encryption enabled with key {sec_config.jb_key_arn}."
            if no_sec_configs:
                report.status = "FAIL"
                report.status_extended = f"Glue development endpoint {endpoint.name} does not have security configuration."
            findings.append(report)
        return findings
