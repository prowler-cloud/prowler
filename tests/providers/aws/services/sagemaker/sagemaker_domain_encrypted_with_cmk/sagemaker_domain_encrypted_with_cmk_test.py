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
test_kms_key_id = (
    f"arn:aws:kms:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:key/test-key-id"
)


class Test_sagemaker_domain_encrypted_with_cmk:
    def test_no_domains(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_domains = []

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_domain_encrypted_with_cmk.sagemaker_domain_encrypted_with_cmk.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_domain_encrypted_with_cmk.sagemaker_domain_encrypted_with_cmk import (
                sagemaker_domain_encrypted_with_cmk,
            )

            check = sagemaker_domain_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 0

    def test_domain_encrypted_with_cmk(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_domains = [
            Domain(
                domain_id=test_domain_id,
                name=test_domain_name,
                arn=domain_arn,
                region=AWS_REGION_EU_WEST_1,
                kms_key_id=test_kms_key_id,
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_domain_encrypted_with_cmk.sagemaker_domain_encrypted_with_cmk.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_domain_encrypted_with_cmk.sagemaker_domain_encrypted_with_cmk import (
                sagemaker_domain_encrypted_with_cmk,
            )

            check = sagemaker_domain_encrypted_with_cmk()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SageMaker domain {test_domain_name} encrypts its EFS and EBS volumes with the customer-managed KMS key {test_kms_key_id}."
            )
            assert result[0].resource_id == test_domain_name
            assert result[0].resource_arn == domain_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_domain_not_encrypted_with_cmk(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_domains = [
            Domain(
                domain_id=test_domain_id,
                name=test_domain_name,
                arn=domain_arn,
                region=AWS_REGION_EU_WEST_1,
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_domain_encrypted_with_cmk.sagemaker_domain_encrypted_with_cmk.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_domain_encrypted_with_cmk.sagemaker_domain_encrypted_with_cmk import (
                sagemaker_domain_encrypted_with_cmk,
            )

            check = sagemaker_domain_encrypted_with_cmk()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SageMaker domain {test_domain_name} does not encrypt its EFS and EBS volumes with a customer-managed KMS key."
            )
            assert result[0].resource_id == test_domain_name
            assert result[0].resource_arn == domain_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_domain_details_not_retrieved(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_domains = [
            Domain(
                domain_id=test_domain_id,
                name=test_domain_name,
                arn=domain_arn,
                region=AWS_REGION_EU_WEST_1,
                detail_fetch_error="ClientError",
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_domain_encrypted_with_cmk.sagemaker_domain_encrypted_with_cmk.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_domain_encrypted_with_cmk.sagemaker_domain_encrypted_with_cmk import (
                sagemaker_domain_encrypted_with_cmk,
            )

            check = sagemaker_domain_encrypted_with_cmk()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"SageMaker domain {test_domain_name} details could not be described (ClientError); volume encryption cannot be verified."
            )
            assert result[0].resource_id == test_domain_name
            assert result[0].resource_arn == domain_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
