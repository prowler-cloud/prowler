from prowler.lib.check.models import Check, Check_Report_AWS, Severity
from prowler.providers.aws.services.acm.acm_client import acm_client


class acm_certificates_expiration_check(Check):
    def execute(self):
        findings = []
        for certificate in acm_client.certificates.values():
            if certificate.in_use or acm_client.provider.scan_unused_services:
                report = Check_Report_AWS(self.metadata())
                report.region = certificate.region
                if certificate.expiration_days > acm_client.audit_config.get(
                    "days_to_expire_threshold", 7
                ):
                    report.status = "PASS"
                    report.status_extended = f"ACM Certificate {certificate.id} for {certificate.name} expires in {certificate.expiration_days} days."
                    report.resource_id = certificate.id
                    report.resource_details = certificate.name
                    report.resource_arn = certificate.arn
                    report.resource_tags = certificate.tags
                else:
                    report.status = "FAIL"
                    if certificate.expiration_days < 0:
                        report.status_extended = f"ACM Certificate {certificate.id} for {certificate.name} has expired ({abs(certificate.expiration_days)} days ago)."
                        report.check_metadata.Severity = Severity.high
                    else:
                        report.status_extended = f"ACM Certificate {certificate.id} for {certificate.name} is about to expire in {certificate.expiration_days} days."
                        report.check_metadata.Severity = Severity.medium

                    report.resource_id = certificate.id
                    report.resource_details = certificate.name
                    report.resource_arn = certificate.arn
                    report.resource_tags = certificate.tags

                findings.append(report)
        return findings
