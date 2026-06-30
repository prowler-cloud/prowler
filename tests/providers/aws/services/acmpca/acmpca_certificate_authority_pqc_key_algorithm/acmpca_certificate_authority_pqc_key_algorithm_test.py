from unittest import mock

from prowler.providers.aws.services.acmpca.acmpca_service import CertificateAuthority
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CA_ID = "12345678-1234-1234-1234-123456789012"
CA_ARN = f"arn:aws:acm-pca:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:certificate-authority/{CA_ID}"


def _build_client(certificate_authorities, audit_config=None):
    acmpca_client = mock.MagicMock()
    acmpca_client.certificate_authorities = certificate_authorities
    acmpca_client.audit_config = audit_config or {}
    return acmpca_client


def _ca(key_algorithm: str, status: str = "ACTIVE"):
    return CertificateAuthority(
        arn=CA_ARN,
        id=CA_ID,
        region=AWS_REGION_US_EAST_1,
        status=status,
        type="SUBORDINATE",
        usage_mode="GENERAL_PURPOSE",
        key_algorithm=key_algorithm,
        signing_algorithm="ML_DSA_65" if "ML_DSA" in key_algorithm else "SHA256WITHRSA",
    )


class Test_acmpca_certificate_authority_pqc_key_algorithm:
    def test_no_cas(self):
        acmpca_client = _build_client({})
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.acmpca.acmpca_certificate_authority_pqc_key_algorithm.acmpca_certificate_authority_pqc_key_algorithm.acmpca_client",
                new=acmpca_client,
            ),
        ):
            from prowler.providers.aws.services.acmpca.acmpca_certificate_authority_pqc_key_algorithm.acmpca_certificate_authority_pqc_key_algorithm import (
                acmpca_certificate_authority_pqc_key_algorithm,
            )

            check = acmpca_certificate_authority_pqc_key_algorithm()
            result = check.execute()
            assert len(result) == 0

    def test_ml_dsa_65(self):
        acmpca_client = _build_client({CA_ARN: _ca("ML_DSA_65")})
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.acmpca.acmpca_certificate_authority_pqc_key_algorithm.acmpca_certificate_authority_pqc_key_algorithm.acmpca_client",
                new=acmpca_client,
            ),
        ):
            from prowler.providers.aws.services.acmpca.acmpca_certificate_authority_pqc_key_algorithm.acmpca_certificate_authority_pqc_key_algorithm import (
                acmpca_certificate_authority_pqc_key_algorithm,
            )

            check = acmpca_certificate_authority_pqc_key_algorithm()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "ML_DSA_65" in result[0].status_extended
            assert result[0].resource_id == CA_ID
            assert result[0].resource_arn == CA_ARN

    def test_rsa_2048_fails(self):
        acmpca_client = _build_client({CA_ARN: _ca("RSA_2048")})
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.acmpca.acmpca_certificate_authority_pqc_key_algorithm.acmpca_certificate_authority_pqc_key_algorithm.acmpca_client",
                new=acmpca_client,
            ),
        ):
            from prowler.providers.aws.services.acmpca.acmpca_certificate_authority_pqc_key_algorithm.acmpca_certificate_authority_pqc_key_algorithm import (
                acmpca_certificate_authority_pqc_key_algorithm,
            )

            check = acmpca_certificate_authority_pqc_key_algorithm()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "RSA_2048" in result[0].status_extended

    def test_deleted_ca_skipped(self):
        acmpca_client = _build_client({CA_ARN: _ca("RSA_2048", status="DELETED")})
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.acmpca.acmpca_certificate_authority_pqc_key_algorithm.acmpca_certificate_authority_pqc_key_algorithm.acmpca_client",
                new=acmpca_client,
            ),
        ):
            from prowler.providers.aws.services.acmpca.acmpca_certificate_authority_pqc_key_algorithm.acmpca_certificate_authority_pqc_key_algorithm import (
                acmpca_certificate_authority_pqc_key_algorithm,
            )

            check = acmpca_certificate_authority_pqc_key_algorithm()
            result = check.execute()

            assert len(result) == 0

    def test_configurable_allowlist(self):
        acmpca_client = _build_client(
            {CA_ARN: _ca("RSA_2048")},
            audit_config={"acmpca_pqc_key_algorithms": ["ML_DSA_65", "RSA_2048"]},
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.acmpca.acmpca_certificate_authority_pqc_key_algorithm.acmpca_certificate_authority_pqc_key_algorithm.acmpca_client",
                new=acmpca_client,
            ),
        ):
            from prowler.providers.aws.services.acmpca.acmpca_certificate_authority_pqc_key_algorithm.acmpca_certificate_authority_pqc_key_algorithm import (
                acmpca_certificate_authority_pqc_key_algorithm,
            )

            check = acmpca_certificate_authority_pqc_key_algorithm()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
