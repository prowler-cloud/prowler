from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.glue.glue_client import glue_client


class glue_development_endpoints_s3_encryption_enabled(Check):
    def execute(self):
        findings = []
        for endpoint in glue_client.dev_endpoints:
            no_sec_configs = True
            report = Check_Report_AWS(self.metadata())
            report.resource_id = endpoint.name
            report.region = endpoint.region
            for sec_config in glue_client.security_configs:
                if sec_config.name == endpoint.security:
                    no_sec_configs = False
                    report.status = "FAIL"
                    report.status_extended = f"Glue development endpoint {endpoint.name} does not have S3 encryption enabled."
                    if sec_config.s3_encryption != "DISABLED":
                        report.status = "PASS"
                        report.status_extended = f"Glue development endpoint {endpoint.name} has S3 encryption enabled with key {sec_config.s3_key_arn}."
            if no_sec_configs:
                report.status = "FAIL"
                report.status_extended = f"Glue development endpoint {endpoint.name} does not have security configuration."
            findings.append(report)
        return findings
