from unittest import mock

from prowler.providers.aws.services.sagemaker.sagemaker_service import Domain
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

test_domain_name = "test-domain"
test_domain_id = "d-testdomain123"
domain_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:domain/{test_domain_id}"


def run_check(domain):
    sagemaker_client = mock.MagicMock
    sagemaker_client.sagemaker_domains = [] if domain is None else [domain]
    aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_domain_vpc_only_enabled.sagemaker_domain_vpc_only_enabled.sagemaker_client",
            sagemaker_client,
        ),
    ):
        from prowler.providers.aws.services.sagemaker.sagemaker_domain_vpc_only_enabled.sagemaker_domain_vpc_only_enabled import (
            sagemaker_domain_vpc_only_enabled,
        )

        return sagemaker_domain_vpc_only_enabled().execute()


class Test_sagemaker_domain_vpc_only_enabled:
    def test_no_domains(self):
        assert run_check(None) == []

    def test_domain_with_vpc_only_network_access(self):
        result = run_check(
            Domain(
                domain_id=test_domain_id,
                name=test_domain_name,
                arn=domain_arn,
                region=AWS_REGION_EU_WEST_1,
                app_network_access_type="VpcOnly",
                details_retrieved=True,
            )
        )

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"SageMaker domain {test_domain_name} uses VPC-only network access."
        )
        assert result[0].resource_id == test_domain_name
        assert result[0].resource_arn == domain_arn

    def test_domain_with_public_or_missing_network_access(self):
        for network_access_type in ("PublicInternetOnly", None):
            result = run_check(
                Domain(
                    domain_id=test_domain_id,
                    name=test_domain_name,
                    arn=domain_arn,
                    region=AWS_REGION_EU_WEST_1,
                    app_network_access_type=network_access_type,
                    details_retrieved=True,
                )
            )

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SageMaker domain {test_domain_name} does not use VPC-only network access."
            )

    def test_domain_with_unavailable_details_requires_manual_review(self):
        result = run_check(
            Domain(
                domain_id=test_domain_id,
                name=test_domain_name,
                arn=domain_arn,
                region=AWS_REGION_EU_WEST_1,
            )
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"SageMaker domain {test_domain_name} details could not be retrieved; manual review is required to verify VPC-only network access."
        )
