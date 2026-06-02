from unittest import mock

from prowler.providers.aws.services.acmpca.acmpca_service import CertificateAuthority
from prowler.providers.aws.services.rolesanywhere.rolesanywhere_service import (
    TrustAnchor,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

TA_ID = "11111111-2222-3333-4444-555555555555"
TA_NAME = "pqc-trust"
TA_ARN = f"arn:aws:rolesanywhere:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:trust-anchor/{TA_ID}"
PCA_ID = "12345678-1234-1234-1234-123456789012"
PCA_ARN = f"arn:aws:acm-pca:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:certificate-authority/{PCA_ID}"


def _trust_anchor(*, source_type: str, acm_pca_arn: str = ""):
    return TrustAnchor(
        arn=TA_ARN,
        id=TA_ID,
        name=TA_NAME,
        region=AWS_REGION_US_EAST_1,
        enabled=True,
        source_type=source_type,
        acm_pca_arn=acm_pca_arn,
    )


def _ca(key_algorithm: str):
    return CertificateAuthority(
        arn=PCA_ARN,
        id=PCA_ID,
        region=AWS_REGION_US_EAST_1,
        status="ACTIVE",
        type="SUBORDINATE",
        usage_mode="GENERAL_PURPOSE",
        key_algorithm=key_algorithm,
        signing_algorithm=(
            key_algorithm if "ML_DSA" in key_algorithm else "SHA256WITHRSA"
        ),
    )


def _build_clients(trust_anchors, certificate_authorities=None, audit_config=None):
    ra_client = mock.MagicMock()
    ra_client.trust_anchors = trust_anchors
    ra_client.audit_config = audit_config or {}
    pca_client = mock.MagicMock()
    pca_client.certificate_authorities = certificate_authorities or {}
    return ra_client, pca_client


def _patched(ra_client, pca_client):
    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    return [
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(
            "prowler.providers.aws.services.rolesanywhere.rolesanywhere_trust_anchor_pqc_pki.rolesanywhere_trust_anchor_pqc_pki.rolesanywhere_client",
            new=ra_client,
        ),
        mock.patch(
            "prowler.providers.aws.services.rolesanywhere.rolesanywhere_trust_anchor_pqc_pki.rolesanywhere_trust_anchor_pqc_pki.acmpca_client",
            new=pca_client,
        ),
    ]


def _enter(patches):
    from contextlib import ExitStack

    stack = ExitStack()
    for p in patches:
        stack.enter_context(p)
    return stack


class Test_rolesanywhere_trust_anchor_pqc_pki:
    def test_no_trust_anchors(self):
        ra_client, pca_client = _build_clients({})
        with _enter(_patched(ra_client, pca_client)):
            from prowler.providers.aws.services.rolesanywhere.rolesanywhere_trust_anchor_pqc_pki.rolesanywhere_trust_anchor_pqc_pki import (
                rolesanywhere_trust_anchor_pqc_pki,
            )

            result = rolesanywhere_trust_anchor_pqc_pki().execute()
            assert len(result) == 0

    def test_pca_backed_pqc(self):
        ra_client, pca_client = _build_clients(
            {TA_ARN: _trust_anchor(source_type="AWS_ACM_PCA", acm_pca_arn=PCA_ARN)},
            certificate_authorities={PCA_ARN: _ca("ML_DSA_65")},
        )
        with _enter(_patched(ra_client, pca_client)):
            from prowler.providers.aws.services.rolesanywhere.rolesanywhere_trust_anchor_pqc_pki.rolesanywhere_trust_anchor_pqc_pki import (
                rolesanywhere_trust_anchor_pqc_pki,
            )

            result = rolesanywhere_trust_anchor_pqc_pki().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "ML_DSA_65" in result[0].status_extended
            assert result[0].resource_id == TA_ID
            assert result[0].resource_arn == TA_ARN

    def test_pca_backed_rsa(self):
        ra_client, pca_client = _build_clients(
            {TA_ARN: _trust_anchor(source_type="AWS_ACM_PCA", acm_pca_arn=PCA_ARN)},
            certificate_authorities={PCA_ARN: _ca("RSA_2048")},
        )
        with _enter(_patched(ra_client, pca_client)):
            from prowler.providers.aws.services.rolesanywhere.rolesanywhere_trust_anchor_pqc_pki.rolesanywhere_trust_anchor_pqc_pki import (
                rolesanywhere_trust_anchor_pqc_pki,
            )

            result = rolesanywhere_trust_anchor_pqc_pki().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "RSA_2048" in result[0].status_extended

    def test_pca_not_in_inventory(self):
        ra_client, pca_client = _build_clients(
            {TA_ARN: _trust_anchor(source_type="AWS_ACM_PCA", acm_pca_arn=PCA_ARN)},
            certificate_authorities={},
        )
        with _enter(_patched(ra_client, pca_client)):
            from prowler.providers.aws.services.rolesanywhere.rolesanywhere_trust_anchor_pqc_pki.rolesanywhere_trust_anchor_pqc_pki import (
                rolesanywhere_trust_anchor_pqc_pki,
            )

            result = rolesanywhere_trust_anchor_pqc_pki().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "could not be inspected" in result[0].status_extended

    def test_certificate_bundle_source(self):
        ra_client, pca_client = _build_clients(
            {TA_ARN: _trust_anchor(source_type="CERTIFICATE_BUNDLE")},
        )
        with _enter(_patched(ra_client, pca_client)):
            from prowler.providers.aws.services.rolesanywhere.rolesanywhere_trust_anchor_pqc_pki.rolesanywhere_trust_anchor_pqc_pki import (
                rolesanywhere_trust_anchor_pqc_pki,
            )

            result = rolesanywhere_trust_anchor_pqc_pki().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "CERTIFICATE_BUNDLE" in result[0].status_extended
