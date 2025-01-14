from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.acm.acm_client import acm_client


class acm_certificates_transparency_logs_enabled(Check):
    def execute(self):
        findings = []
        for certificate in acm_client.certificates.values():
            if certificate.in_use or acm_client.provider.scan_unused_services:
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource_metadata=certificate
                )
                if certificate.type == "IMPORTED":
                    report.status = "PASS"
                    report.status_extended = f"ACM Certificate {certificate.id} for {certificate.name} is imported."
                else:
                    if not certificate.transparency_logging:
                        report.status = "FAIL"
                        report.status_extended = f"ACM Certificate {certificate.id} for {certificate.name} has Certificate Transparency logging disabled."
                    else:
                        report.status = "PASS"
                        report.status_extended = f"ACM Certificate {certificate.id} for {certificate.name} has Certificate Transparency logging enabled."
                findings.append(report)
        return findings
