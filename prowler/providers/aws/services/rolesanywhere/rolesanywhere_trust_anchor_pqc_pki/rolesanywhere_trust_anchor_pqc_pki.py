from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.acmpca.acmpca_client import acmpca_client
from prowler.providers.aws.services.rolesanywhere.rolesanywhere_client import (
    rolesanywhere_client,
)

PQC_PCA_KEY_ALGORITHMS_DEFAULT = [
    "ML_DSA_44",
    "ML_DSA_65",
    "ML_DSA_87",
]


class rolesanywhere_trust_anchor_pqc_pki(Check):
    """Verify that IAM Roles Anywhere trust anchors are backed by a post-quantum PKI.

    For trust anchors whose source is ``AWS_ACM_PCA``, the linked Private CA's
    ``KeyAlgorithm`` is checked against the configured ML-DSA allowlist.
    Trust anchors backed by an external ``CERTIFICATE_BUNDLE`` are reported as
    FAIL because their certificate signature algorithm cannot be inspected
    from the IAM Roles Anywhere API alone.
    """

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        pqc_algorithms = rolesanywhere_client.audit_config.get(
            "rolesanywhere_pqc_pca_key_algorithms", PQC_PCA_KEY_ALGORITHMS_DEFAULT
        )
        for trust_anchor in rolesanywhere_client.trust_anchors.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=trust_anchor)
            if trust_anchor.source_type == "AWS_ACM_PCA":
                linked_ca = acmpca_client.certificate_authorities.get(
                    trust_anchor.acm_pca_arn
                )
                if linked_ca and linked_ca.key_algorithm in pqc_algorithms:
                    report.status = "PASS"
                    report.status_extended = (
                        f"IAM Roles Anywhere trust anchor {trust_anchor.name} is "
                        f"backed by Private CA {linked_ca.id} using post-quantum "
                        f"key algorithm {linked_ca.key_algorithm}."
                    )
                elif linked_ca:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"IAM Roles Anywhere trust anchor {trust_anchor.name} is "
                        f"backed by Private CA {linked_ca.id} using key algorithm "
                        f"{linked_ca.key_algorithm or '<unknown>'}, which is not "
                        "post-quantum (ML-DSA)."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"IAM Roles Anywhere trust anchor {trust_anchor.name} is "
                        f"backed by Private CA {trust_anchor.acm_pca_arn}, which "
                        "could not be inspected (cross-account or missing "
                        "acm-pca permissions). Verify the CA uses an ML-DSA key "
                        "algorithm."
                    )
            else:
                source = trust_anchor.source_type or "<none>"
                report.status = "FAIL"
                report.status_extended = (
                    f"IAM Roles Anywhere trust anchor {trust_anchor.name} uses "
                    f"source type {source}; the certificate signature algorithm "
                    "cannot be inspected automatically. Migrate to an AWS Private "
                    "CA using an ML-DSA key algorithm to enable post-quantum "
                    "evaluation."
                )
            findings.append(report)

        return findings
