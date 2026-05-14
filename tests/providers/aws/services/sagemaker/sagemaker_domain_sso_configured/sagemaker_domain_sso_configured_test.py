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
test_sso_instance_id = "app-test-instance-id"
test_sso_application_arn = (
    f"arn:aws:sso::{AWS_ACCOUNT_NUMBER}:application/sagemaker/apl-test"
)


class Test_sagemaker_domain_sso_configured:
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
                "prowler.providers.aws.services.sagemaker.sagemaker_domain_sso_configured.sagemaker_domain_sso_configured.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_domain_sso_configured.sagemaker_domain_sso_configured import (
                sagemaker_domain_sso_configured,
            )

            check = sagemaker_domain_sso_configured()
            result = check.execute()
            assert len(result) == 0

    def test_domain_sso_configured_with_instance_id(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_domains = [
            Domain(
                domain_id=test_domain_id,
                name=test_domain_name,
                arn=domain_arn,
                region=AWS_REGION_EU_WEST_1,
                auth_mode="SSO",
                single_sign_on_managed_application_instance_id=test_sso_instance_id,
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_domain_sso_configured.sagemaker_domain_sso_configured.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_domain_sso_configured.sagemaker_domain_sso_configured import (
                sagemaker_domain_sso_configured,
            )

            check = sagemaker_domain_sso_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SageMaker domain {test_domain_name} is configured with SSO authentication and is associated with an IAM Identity Center instance."
            )
            assert result[0].resource_id == test_domain_name
            assert result[0].resource_arn == domain_arn

    def test_domain_sso_configured_with_application_arn(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_domains = [
            Domain(
                domain_id=test_domain_id,
                name=test_domain_name,
                arn=domain_arn,
                region=AWS_REGION_EU_WEST_1,
                auth_mode="SSO",
                single_sign_on_application_arn=test_sso_application_arn,
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_domain_sso_configured.sagemaker_domain_sso_configured.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_domain_sso_configured.sagemaker_domain_sso_configured import (
                sagemaker_domain_sso_configured,
            )

            check = sagemaker_domain_sso_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SageMaker domain {test_domain_name} is configured with SSO authentication and is associated with an IAM Identity Center instance."
            )

    def test_domain_sso_without_identity_center(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_domains = [
            Domain(
                domain_id=test_domain_id,
                name=test_domain_name,
                arn=domain_arn,
                region=AWS_REGION_EU_WEST_1,
                auth_mode="SSO",
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_domain_sso_configured.sagemaker_domain_sso_configured.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_domain_sso_configured.sagemaker_domain_sso_configured import (
                sagemaker_domain_sso_configured,
            )

            check = sagemaker_domain_sso_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SageMaker domain {test_domain_name} is configured with SSO authentication but is not associated with an IAM Identity Center instance."
            )
            assert result[0].resource_id == test_domain_name
            assert result[0].resource_arn == domain_arn

    def test_domain_iam_mode(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_domains = [
            Domain(
                domain_id=test_domain_id,
                name=test_domain_name,
                arn=domain_arn,
                region=AWS_REGION_EU_WEST_1,
                auth_mode="IAM",
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_domain_sso_configured.sagemaker_domain_sso_configured.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_domain_sso_configured.sagemaker_domain_sso_configured import (
                sagemaker_domain_sso_configured,
            )

            check = sagemaker_domain_sso_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SageMaker domain {test_domain_name} is not configured with SSO authentication, current mode is IAM."
            )
            assert result[0].resource_id == test_domain_name
            assert result[0].resource_arn == domain_arn

    def test_domain_auth_mode_unknown(self):
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
                "prowler.providers.aws.services.sagemaker.sagemaker_domain_sso_configured.sagemaker_domain_sso_configured.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_domain_sso_configured.sagemaker_domain_sso_configured import (
                sagemaker_domain_sso_configured,
            )

            check = sagemaker_domain_sso_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SageMaker domain {test_domain_name} is not configured with SSO authentication, current mode is unknown."
            )
