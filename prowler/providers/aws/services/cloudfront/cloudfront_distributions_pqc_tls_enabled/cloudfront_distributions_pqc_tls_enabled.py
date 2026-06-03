from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)

PQC_CLOUDFRONT_POLICIES_DEFAULT = [
    "TLSv1.3_2025",
]


class cloudfront_distributions_pqc_tls_enabled(Check):
    """Verify that every CloudFront distribution enforces TLS 1.3 with post-quantum key exchange.

    Quantum-safe key exchanges (``X25519MLKEM768``, ``SecP256r1MLKEM768``) are
    only available on TLS 1.3 viewer connections. A distribution PASSES when
    its ``MinimumProtocolVersion`` belongs to the configured allowlist of
    TLS 1.3-only policies. Distributions that rely on the default CloudFront
    certificate are pinned to the legacy ``TLSv1`` policy and therefore FAIL.
    """

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        pqc_policies = cloudfront_client.audit_config.get(
            "cloudfront_pqc_min_protocol_versions", PQC_CLOUDFRONT_POLICIES_DEFAULT
        )
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=distribution)
            policy = distribution.minimum_protocol_version or "<none>"
            if distribution.default_certificate:
                report.status = "FAIL"
                report.status_extended = (
                    f"CloudFront Distribution {distribution.id} uses the default "
                    "CloudFront certificate, which pins the security policy to "
                    "TLSv1 and cannot enable post-quantum TLS."
                )
            elif distribution.minimum_protocol_version in pqc_policies:
                report.status = "PASS"
                report.status_extended = (
                    f"CloudFront Distribution {distribution.id} uses post-quantum "
                    f"TLS policy {policy}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"CloudFront Distribution {distribution.id} uses TLS policy "
                    f"{policy}, which is not in the post-quantum allowlist."
                )
            findings.append(report)

        return findings
