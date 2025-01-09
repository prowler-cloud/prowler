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
repo_policy_not_public = {
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

repo_policy_public = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ECRRepositoryPolicy",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": ["ecr:DescribeImages", "ecr:DescribeRepositories"],
        }
    ],
}


class Test_ecr_repositories_not_publicly_accessible:
    # Mocked Audit Info

    def test_no_registries(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_not_publicly_accessible.ecr_repositories_not_publicly_accessible.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_not_publicly_accessible.ecr_repositories_not_publicly_accessible import (
                ecr_repositories_not_publicly_accessible,
            )

            check = ecr_repositories_not_publicly_accessible()
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
            "prowler.providers.aws.services.ecr.ecr_repositories_not_publicly_accessible.ecr_repositories_not_publicly_accessible.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_not_publicly_accessible.ecr_repositories_not_publicly_accessible import (
                ecr_repositories_not_publicly_accessible,
            )

            check = ecr_repositories_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 0

    def test_repository_not_public(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.audit_config = {}
        ecr_client.audited_account = AWS_ACCOUNT_NUMBER
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    policy=repo_policy_not_public,
                    images_details=None,
                    lifecycle_policy=None,
                )
            ],
            rules=[],
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_not_publicly_accessible.ecr_repositories_not_publicly_accessible.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_not_publicly_accessible.ecr_repositories_not_publicly_accessible import (
                ecr_repositories_not_publicly_accessible,
            )

            check = ecr_repositories_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Repository {repository_name} is not publicly accessible."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn

    def test_repository_no_policy(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    policy=None,
                    images_details=None,
                    lifecycle_policy=None,
                )
            ],
            rules=[],
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_not_publicly_accessible.ecr_repositories_not_publicly_accessible.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_not_publicly_accessible.ecr_repositories_not_publicly_accessible import (
                ecr_repositories_not_publicly_accessible,
            )

            check = ecr_repositories_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Repository {repository_name} is not publicly accessible."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn

    def test_repository_public(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.audit_config = {}
        ecr_client.audited_account = AWS_ACCOUNT_NUMBER
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=None,
                    lifecycle_policy=None,
                )
            ],
            rules=[],
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_not_publicly_accessible.ecr_repositories_not_publicly_accessible.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_not_publicly_accessible.ecr_repositories_not_publicly_accessible import (
                ecr_repositories_not_publicly_accessible,
            )

            check = ecr_repositories_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Repository {repository_name} is publicly accessible."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn
