from unittest import mock

from moto import mock_aws

from prowler.providers.aws.services.apigateway.apigateway_service import DomainName
from tests.providers.aws.utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

DOMAIN_NAME = "api.example.com"
DOMAIN_ARN = f"arn:aws:apigateway:{AWS_REGION_US_EAST_1}::/domainnames/{DOMAIN_NAME}"


def _build_client(security_policy: str):
    apigw_client = mock.MagicMock()
    apigw_client.audit_config = {}
    apigw_client.domain_names = [
        DomainName(
            name=DOMAIN_NAME,
            arn=DOMAIN_ARN,
            region=AWS_REGION_US_EAST_1,
            security_policy=security_policy,
        )
    ]
    return apigw_client


class Test_apigateway_domain_name_pqc_tls_enabled:
    @mock_aws
    def test_no_domains(self):
        apigw_client = mock.MagicMock()
        apigw_client.audit_config = {}
        apigw_client.domain_names = []

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.apigateway.apigateway_domain_name_pqc_tls_enabled.apigateway_domain_name_pqc_tls_enabled.apigateway_client",
                new=apigw_client,
            ):
                from prowler.providers.aws.services.apigateway.apigateway_domain_name_pqc_tls_enabled.apigateway_domain_name_pqc_tls_enabled import (
                    apigateway_domain_name_pqc_tls_enabled,
                )

                check = apigateway_domain_name_pqc_tls_enabled()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_pq_policy(self):
        apigw_client = _build_client("SecurityPolicy_TLS13_1_3_2025_09")

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.apigateway.apigateway_domain_name_pqc_tls_enabled.apigateway_domain_name_pqc_tls_enabled.apigateway_client",
                new=apigw_client,
            ):
                from prowler.providers.aws.services.apigateway.apigateway_domain_name_pqc_tls_enabled.apigateway_domain_name_pqc_tls_enabled import (
                    apigateway_domain_name_pqc_tls_enabled,
                )

                check = apigateway_domain_name_pqc_tls_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert "SecurityPolicy_TLS13_1_3_2025_09" in result[0].status_extended
                assert result[0].resource_id == DOMAIN_NAME
                assert result[0].resource_arn == DOMAIN_ARN
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_alternate_pq_policy(self):
        apigw_client = _build_client("SecurityPolicy_TLS13_1_2_PQ_2025_09")

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.apigateway.apigateway_domain_name_pqc_tls_enabled.apigateway_domain_name_pqc_tls_enabled.apigateway_client",
                new=apigw_client,
            ):
                from prowler.providers.aws.services.apigateway.apigateway_domain_name_pqc_tls_enabled.apigateway_domain_name_pqc_tls_enabled import (
                    apigateway_domain_name_pqc_tls_enabled,
                )

                check = apigateway_domain_name_pqc_tls_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    "SecurityPolicy_TLS13_1_2_PQ_2025_09" in result[0].status_extended
                )

    @mock_aws
    def test_legacy_tls_1_2(self):
        apigw_client = _build_client("TLS_1_2")

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.apigateway.apigateway_domain_name_pqc_tls_enabled.apigateway_domain_name_pqc_tls_enabled.apigateway_client",
                new=apigw_client,
            ):
                from prowler.providers.aws.services.apigateway.apigateway_domain_name_pqc_tls_enabled.apigateway_domain_name_pqc_tls_enabled import (
                    apigateway_domain_name_pqc_tls_enabled,
                )

                check = apigateway_domain_name_pqc_tls_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert "TLS_1_2" in result[0].status_extended
                assert "not in the post-quantum allowlist" in result[0].status_extended

    @mock_aws
    def test_missing_security_policy(self):
        apigw_client = _build_client("")

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.apigateway.apigateway_domain_name_pqc_tls_enabled.apigateway_domain_name_pqc_tls_enabled.apigateway_client",
                new=apigw_client,
            ):
                from prowler.providers.aws.services.apigateway.apigateway_domain_name_pqc_tls_enabled.apigateway_domain_name_pqc_tls_enabled import (
                    apigateway_domain_name_pqc_tls_enabled,
                )

                check = apigateway_domain_name_pqc_tls_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert "<none>" in result[0].status_extended

    @mock_aws
    def test_configurable_allowlist(self):
        apigw_client = _build_client("TLS_1_2")
        apigw_client.audit_config = {
            "apigateway_pqc_tls_allowed_policies": [
                "SecurityPolicy_TLS13_1_3_2025_09",
                "TLS_1_2",
            ]
        }

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.apigateway.apigateway_domain_name_pqc_tls_enabled.apigateway_domain_name_pqc_tls_enabled.apigateway_client",
                new=apigw_client,
            ):
                from prowler.providers.aws.services.apigateway.apigateway_domain_name_pqc_tls_enabled.apigateway_domain_name_pqc_tls_enabled import (
                    apigateway_domain_name_pqc_tls_enabled,
                )

                check = apigateway_domain_name_pqc_tls_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"

    @mock_aws
    def test_null_config_uses_default_allowlist(self):
        apigw_client = _build_client("SecurityPolicy_TLS13_1_3_2025_09")
        apigw_client.audit_config = {
            "apigateway_pqc_tls_allowed_policies": None,
        }

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.apigateway.apigateway_domain_name_pqc_tls_enabled.apigateway_domain_name_pqc_tls_enabled.apigateway_client",
                new=apigw_client,
            ):
                from prowler.providers.aws.services.apigateway.apigateway_domain_name_pqc_tls_enabled.apigateway_domain_name_pqc_tls_enabled import (
                    apigateway_domain_name_pqc_tls_enabled,
                )

                check = apigateway_domain_name_pqc_tls_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"

    @mock_aws
    def test_non_iterable_config_uses_default_allowlist(self):
        apigw_client = _build_client("SecurityPolicy_TLS13_1_3_2025_09")
        apigw_client.audit_config = {
            "apigateway_pqc_tls_allowed_policies": 123,
        }

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.apigateway.apigateway_domain_name_pqc_tls_enabled.apigateway_domain_name_pqc_tls_enabled.apigateway_client",
                new=apigw_client,
            ):
                from prowler.providers.aws.services.apigateway.apigateway_domain_name_pqc_tls_enabled.apigateway_domain_name_pqc_tls_enabled import (
                    apigateway_domain_name_pqc_tls_enabled,
                )

                check = apigateway_domain_name_pqc_tls_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
