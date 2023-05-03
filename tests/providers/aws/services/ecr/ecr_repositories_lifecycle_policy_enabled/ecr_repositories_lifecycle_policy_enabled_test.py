from re import search
from unittest import mock

from prowler.providers.aws.services.ecr.ecr_service import Repository

# Mock Test Region
AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"
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
    def test_no_lifecycle_policy(self):
        ecr_client = mock.MagicMock
        ecr_client.repositories = []
        ecr_client.repositories.append(
            Repository(
                name=repository_name,
                arn=repository_arn,
                region=AWS_REGION,
                scan_on_push=True,
                policy=repo_policy_public,
                images_details=None,
                lifecycle_policy="test-policy",
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.ecr.ecr_service.ECR",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_lifecycle_policy_enabled.ecr_repositories_lifecycle_policy_enabled import (
                ecr_repositories_lifecycle_policy_enabled,
            )

            check = ecr_repositories_lifecycle_policy_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search("has lifecycle policy", result[0].status_extended)
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn

    def test_lifecycle_policy(self):
        ecr_client = mock.MagicMock
        ecr_client.repositories = []
        ecr_client.repositories.append(
            Repository(
                name=repository_name,
                arn=repository_arn,
                region=AWS_REGION,
                scan_on_push=False,
                policy=repo_policy_public,
                images_details=None,
                lifecycle_policy=None,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.ecr.ecr_service.ECR",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_lifecycle_policy_enabled.ecr_repositories_lifecycle_policy_enabled import (
                ecr_repositories_lifecycle_policy_enabled,
            )

            check = ecr_repositories_lifecycle_policy_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search("has no lifecycle policy", result[0].status_extended)
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn
