from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider


class Test_ecr_repositories_not_publicly_accessible_fixer:
    @mock_aws
    def test_ecr_repository_public(self):
        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)

        repository_name = "test-repo"
        ecr_client.create_repository(repositoryName=repository_name)

        ecr_client.set_repository_policy(
            repositoryName=repository_name,
            policyText=dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "*"},
                            "Action": "ecr:*",
                            "Resource": f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:123456789012:repository/{repository_name}",
                        }
                    ],
                }
            ),
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.ecr.ecr_service import ECR

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_not_publicly_accessible.ecr_repositories_not_publicly_accessible_fixer.ecr_client",
            new=ECR(aws_provider),
        ):
            # Test Fixer
            from prowler.providers.aws.services.ecr.ecr_repositories_not_publicly_accessible.ecr_repositories_not_publicly_accessible_fixer import (
                fixer,
            )

            assert fixer(repository_name, AWS_REGION_EU_WEST_1)

    @mock_aws
    def test_ecr_repository_not_public(self):
        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)

        repository_name = "test-repo"
        ecr_client.create_repository(repositoryName=repository_name)

        ecr_client.set_repository_policy(
            repositoryName=repository_name,
            policyText=dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "123456789012"},
                            "Action": "ecr:*",
                            "Resource": f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:123456789012:repository/{repository_name}",
                        }
                    ],
                }
            ),
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.ecr.ecr_service import ECR

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_not_publicly_accessible.ecr_repositories_not_publicly_accessible_fixer.ecr_client",
            new=ECR(aws_provider),
        ):
            # Test Fixer
            from prowler.providers.aws.services.ecr.ecr_repositories_not_publicly_accessible.ecr_repositories_not_publicly_accessible_fixer import (
                fixer,
            )

            assert fixer(repository_name, AWS_REGION_EU_WEST_1)

    @mock_aws
    def test_ecr_repository_public_error(self):
        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)

        repository_name = "test-repo"
        ecr_client.create_repository(repositoryName=repository_name)

        ecr_client.set_repository_policy(
            repositoryName=repository_name,
            policyText=dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "*"},
                            "Action": "ecr:*",
                            "Resource": f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:123456789012:repository/{repository_name}",
                        }
                    ],
                }
            ),
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.ecr.ecr_service import ECR

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_not_publicly_accessible.ecr_repositories_not_publicly_accessible_fixer.ecr_client",
            new=ECR(aws_provider),
        ):
            # Test Fixer
            from prowler.providers.aws.services.ecr.ecr_repositories_not_publicly_accessible.ecr_repositories_not_publicly_accessible_fixer import (
                fixer,
            )

            assert not fixer("repository_name_non_existing", AWS_REGION_EU_WEST_1)
