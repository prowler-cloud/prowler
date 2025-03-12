from unittest import mock

from prowler.providers.aws.services.ecr.ecr_service import Registry, Repository
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

repository_name = "test_repo"
repository_arn = (
    f"arn:aws:ecr:eu-west-1:{AWS_ACCOUNT_NUMBER}:repository/{repository_name}"
)
repo_policy_public = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ECRRepositoryPolicy",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:user/username"},
            "Action": ["ecr:DescribeImages", "ecr:DescribeRepositories"],
        }
    ],
}


class Test_ecr_repositories_lifecycle_policy_enabled:
    # Mocked Audit Info

    def test_no_registries(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_lifecycle_policy_enabled.ecr_repositories_lifecycle_policy_enabled.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_lifecycle_policy_enabled.ecr_repositories_lifecycle_policy_enabled import (
                ecr_repositories_lifecycle_policy_enabled,
            )

            check = ecr_repositories_lifecycle_policy_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_registry_no_repositories(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[],
            rules=[],
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_lifecycle_policy_enabled.ecr_repositories_lifecycle_policy_enabled.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_lifecycle_policy_enabled.ecr_repositories_lifecycle_policy_enabled import (
                ecr_repositories_lifecycle_policy_enabled,
            )

            check = ecr_repositories_lifecycle_policy_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_lifecycle_policy(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            rules=[],
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=None,
                    lifecycle_policy="test-policy",
                )
            ],
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_lifecycle_policy_enabled.ecr_repositories_lifecycle_policy_enabled.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_lifecycle_policy_enabled.ecr_repositories_lifecycle_policy_enabled import (
                ecr_repositories_lifecycle_policy_enabled,
            )

            check = ecr_repositories_lifecycle_policy_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Repository {repository_name} has a lifecycle policy configured."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn
            assert result[0].resource_tags == []

    def test_no_lifecycle_policy(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            rules=[],
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=False,
                    policy=repo_policy_public,
                    images_details=None,
                    lifecycle_policy=None,
                )
            ],
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_lifecycle_policy_enabled.ecr_repositories_lifecycle_policy_enabled.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_lifecycle_policy_enabled.ecr_repositories_lifecycle_policy_enabled import (
                ecr_repositories_lifecycle_policy_enabled,
            )

            check = ecr_repositories_lifecycle_policy_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Repository {repository_name} does not have a lifecycle policy configured."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn
            assert result[0].resource_tags == []
