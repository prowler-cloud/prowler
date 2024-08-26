from prowler.lib.check.models import Check
from prowler.lib.outputs.finding import Finding
from prowler.providers.aws.services.acm.acm_client import acm_client


class acm_certificates_expiration_check(Check):
    def execute(self):
        findings = []
        for certificate in acm_client.certificates:
            if certificate.in_use or acm_client.provider.scan_unused_services:
                finding = {}
                finding["region"] = certificate.region
                if certificate.expiration_days > acm_client.audit_config.get(
                    "days_to_expire_threshold", 7
                ):
                    finding["status"] = "PASS"
                    finding["status_extended"] = (
                        f"ACM Certificate {certificate.id} for {certificate.name} expires in {certificate.expiration_days} days."
                    )
                    finding["resource_id"] = certificate.id
                    finding["resource_details"] = certificate.name
                    finding["resource_arn"] = certificate.arn
                    finding["resource_tags"] = certificate.tags
                else:
                    finding["status"] = "FAIL"
                    if certificate.expiration_days < 0:
                        finding["status_extended"] = (
                            f"ACM Certificate {certificate.id} for {certificate.name} has expired ({abs(certificate.expiration_days)} days ago)."
                        )
                        self.Severity = "high"
                    else:
                        finding["status_extended"] = (
                            f"ACM Certificate {certificate.id} for {certificate.name} is about to expire in {certificate.expiration_days} days."
                        )
                        self.Severity = "medium"

                    finding["resource_id"] = certificate.id
                    finding["resource_details"] = certificate.name
                    finding["resource_arn"] = certificate.arn
                    finding["resource_tags"] = certificate.tags
                findings.append(
                    Finding.generate_finding(acm_client.provider, finding, self)
                )
        return findings
