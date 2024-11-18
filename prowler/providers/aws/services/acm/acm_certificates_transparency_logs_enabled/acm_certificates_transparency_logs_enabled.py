from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.acm.acm_client import acm_client


class acm_certificates_transparency_logs_enabled(Check):
    def execute(self):
        findings = []
        for certificate in acm_client.certificates.values():
            if certificate.in_use or acm_client.provider.scan_unused_services:
                report = Check_Report_AWS(self.metadata())
                report.region = certificate.region
                if certificate.type == "IMPORTED":
                    report.status = "PASS"
                    report.status_extended = f"ACM Certificate {certificate.id} for {certificate.name} is imported."
                    report.resource_id = certificate.id
                    report.resource_details = certificate.name
                    report.resource_arn = certificate.arn
                    report.resource_tags = certificate.tags
                else:
                    if not certificate.transparency_logging:
                        report.status = "FAIL"
                        report.status_extended = f"ACM Certificate {certificate.id} for {certificate.name} has Certificate Transparency logging disabled."
                        report.resource_id = certificate.id
                        report.resource_details = certificate.name
                        report.resource_arn = certificate.arn
                        report.resource_tags = certificate.tags
                    else:
                        report.status = "PASS"
                        report.status_extended = f"ACM Certificate {certificate.id} for {certificate.name} has Certificate Transparency logging enabled."
                        report.resource_id = certificate.id
                        report.resource_details = certificate.name
                        report.resource_arn = certificate.arn
                        report.resource_tags = certificate.tags
                findings.append(report)
        return findings
