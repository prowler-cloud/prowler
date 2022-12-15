from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.acm.acm_client import acm_client

DAYS_TO_EXPIRE_THRESHOLD = 7


class acm_certificates_expiration_check(Check):
    def execute(self):
        findings = []
        for certificate in acm_client.certificates:
            report = Check_Report_AWS(self.metadata())
            report.region = certificate.region
            if certificate.expiration_days > DAYS_TO_EXPIRE_THRESHOLD:
                report.status = "PASS"
                report.status_extended = f"ACM Certificate for {certificate.name} expires in {certificate.expiration_days} days."
                report.resource_id = certificate.name
                report.resource_arn = certificate.arn
            else:
                report.status = "FAIL"
                report.status_extended = f"ACM Certificate for {certificate.name} is about to expire in {DAYS_TO_EXPIRE_THRESHOLD} days."
                report.resource_id = certificate.name
                report.resource_arn = certificate.arn

            findings.append(report)
        return findings
