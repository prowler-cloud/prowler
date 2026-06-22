import sys
from unittest import mock

from prowler.providers.aws.services.cloudfront.cloudfront_service import (
    Distribution,
    Origin,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

DISTRIBUTION_ID = "E27LVI50CSW06W"
DISTRIBUTION_ARN = (
    f"arn:aws:cloudfront::{AWS_ACCOUNT_NUMBER}:distribution/{DISTRIBUTION_ID}"
)
REGION = "us-east-1"
CHECK_MODULE = "prowler.providers.aws.services.cloudfront.cloudfront_distributions_pqc_tls_enabled.cloudfront_distributions_pqc_tls_enabled"
CLIENT_MODULE = "prowler.providers.aws.services.cloudfront.cloudfront_client"


def _clear_cloudfront_modules():
    sys.modules.pop(CHECK_MODULE, None)
    sys.modules.pop(CLIENT_MODULE, None)


def _build_distribution(
    *,
    minimum_protocol_version: str,
    default_certificate: bool = False,
):
    return Distribution(
        arn=DISTRIBUTION_ARN,
        id=DISTRIBUTION_ID,
        region=REGION,
        origins=[
            Origin(
                id="o1",
                domain_name="origin.example.com",
                origin_protocol_policy="https-only",
                origin_ssl_protocols=["TLSv1.2"],
            )
        ],
        origin_failover=False,
        minimum_protocol_version=minimum_protocol_version,
        default_certificate=default_certificate,
    )


def _build_client(distributions: dict, audit_config: dict | None = None):
    cloudfront_client = mock.MagicMock()
    cloudfront_client.distributions = distributions
    cloudfront_client.audit_config = audit_config or {}
    return cloudfront_client


def _execute_check(cloudfront_client):
    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    _clear_cloudfront_modules()

    try:
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
                return_value=cloudfront_client,
            ),
        ):
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_pqc_tls_enabled.cloudfront_distributions_pqc_tls_enabled import (
                cloudfront_distributions_pqc_tls_enabled,
            )

            check = cloudfront_distributions_pqc_tls_enabled()
            return check.execute()
    finally:
        _clear_cloudfront_modules()


class Test_cloudfront_distributions_pqc_tls_enabled:
    def test_no_distributions(self):
        cloudfront_client = _build_client({})

        result = _execute_check(cloudfront_client)

        assert len(result) == 0

    def test_pq_policy_tls13_2025(self):
        cloudfront_client = _build_client(
            {
                DISTRIBUTION_ID: _build_distribution(
                    minimum_protocol_version="TLSv1.3_2025"
                )
            }
        )

        result = _execute_check(cloudfront_client)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "TLSv1.3_2025" in result[0].status_extended
        assert result[0].resource_id == DISTRIBUTION_ID
        assert result[0].resource_arn == DISTRIBUTION_ARN

    def test_classical_tls12_2021(self):
        cloudfront_client = _build_client(
            {
                DISTRIBUTION_ID: _build_distribution(
                    minimum_protocol_version="TLSv1.2_2021"
                )
            }
        )

        result = _execute_check(cloudfront_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "TLSv1.2_2021" in result[0].status_extended
        assert "not in the post-quantum allowlist" in result[0].status_extended

    def test_default_cloudfront_certificate(self):
        cloudfront_client = _build_client(
            {
                DISTRIBUTION_ID: _build_distribution(
                    minimum_protocol_version="TLSv1",
                    default_certificate=True,
                )
            }
        )

        result = _execute_check(cloudfront_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "default CloudFront certificate" in result[0].status_extended

    def test_configurable_allowlist(self):
        cloudfront_client = _build_client(
            {
                DISTRIBUTION_ID: _build_distribution(
                    minimum_protocol_version="TLSv1.2_2021"
                )
            },
            audit_config={
                "cloudfront_pqc_min_protocol_versions": [
                    "TLSv1.3_2025",
                    "TLSv1.2_2021",
                ]
            },
        )

        result = _execute_check(cloudfront_client)

        assert len(result) == 1
        assert result[0].status == "PASS"
