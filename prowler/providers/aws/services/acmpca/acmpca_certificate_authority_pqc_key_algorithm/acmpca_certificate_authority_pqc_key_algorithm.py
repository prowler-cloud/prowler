from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.acmpca.acmpca_client import acmpca_client

PQC_PCA_KEY_ALGORITHMS_DEFAULT = [
    "ML_DSA_44",
    "ML_DSA_65",
    "ML_DSA_87",
]


class acmpca_certificate_authority_pqc_key_algorithm(Check):
    """Verify that every AWS Private CA uses a post-quantum key algorithm.

    A Private CA PASSES when its ``KeyAlgorithm`` belongs to the configured
    allowlist of post-quantum signature algorithms (ML-DSA family).
    Deleted CAs are skipped.
    """

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        pqc_algorithms = acmpca_client.audit_config.get(
            "acmpca_pqc_key_algorithms", PQC_PCA_KEY_ALGORITHMS_DEFAULT
        )
        for ca in acmpca_client.certificate_authorities.values():
            if ca.status == "DELETED":
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=ca)
            algorithm = ca.key_algorithm or "<none>"
            if ca.key_algorithm in pqc_algorithms:
                report.status = "PASS"
                report.status_extended = (
                    f"AWS Private CA {ca.id} uses post-quantum key algorithm "
                    f"{algorithm}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"AWS Private CA {ca.id} uses key algorithm {algorithm}, "
                    "which is not post-quantum (ML-DSA)."
                )
            findings.append(report)

        return findings
