from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.acm.acm_client import acm_client


class acm_certificates_transparency_logs_enabled(Check):
    def execute(self):
        findings = []
        for certificate in acm_client.certificates:
            report = Check_Report_AWS(self.metadata())
            report.region = certificate.region
            if certificate.type == "IMPORTED":
                report.status = "PASS"
                report.status_extended = (
                    f"ACM Certificate for {certificate.name} is imported."
                )
                report.resource_id = certificate.name
                report.resource_arn = certificate.arn
            else:
                if not certificate.transparency_logging:
                    report.status = "FAIL"
                    report.status_extended = f"ACM Certificate for {certificate.name} has Certificate Transparency logging disabled."
                    report.resource_id = certificate.name
                    report.resource_arn = certificate.arn
                else:
                    report.status = "PASS"
                    report.status_extended = f"ACM Certificate for {certificate.name} has Certificate Transparency logging enabled."
                    report.resource_id = certificate.name
                    report.resource_arn = certificate.arn
            findings.append(report)
        return findings
