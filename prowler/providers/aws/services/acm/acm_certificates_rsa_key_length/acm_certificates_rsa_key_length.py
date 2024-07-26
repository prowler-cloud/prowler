from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.acm.acm_client import acm_client


class acm_certificates_rsa_key_length(Check):
    def execute(self):
        findings = []
        for certificate in acm_client.certificates:
            report = Check_Report_AWS(self.metadata())
            report.region = certificate.region
            report.resource_id = certificate.id
            report.resource_details = certificate.name
            report.resource_arn = certificate.arn
            report.resource_tags = certificate.tags

            report.status = "PASS"
            report.status_extended = f"ACM Certificate {certificate.id} for {certificate.name} meet minimum key size requirements."

            if certificate.key_algorithm == "RSA_1024":
                report.status = "FAIL"
                report.status_extended = f"ACM Certificate {certificate.id} for {certificate.name} uses RSA_1024 which is not secure enough."
            findings.append(report)

        return findings
