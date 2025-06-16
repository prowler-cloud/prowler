from unittest.mock import patch

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_codebuild_project_uses_allowed_github_organizations:
    @mock_aws
    def test_no_projects(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client",
                new=Codebuild(aws_provider),
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client.audit_config",
                {"codebuild_github_allowed_organizations": ["allowed-org"]},
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations import (
                codebuild_project_uses_allowed_github_organizations,
            )

            check = codebuild_project_uses_allowed_github_organizations()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_project_github_allowed_organization(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        codebuild_client = client("codebuild", region_name=AWS_REGION_EU_WEST_1)
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        project_name = "test-project-github-allowed"
        role_name = "codebuild-test-role"
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument="""{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "codebuild.amazonaws.com"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            }""",
        )["Role"]["Arn"]
        project_arn = codebuild_client.create_project(
            name=project_name,
            source={
                "type": "GITHUB",
                "location": "https://github.com/allowed-org/repo",
            },
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:4.0",
                "computeType": "BUILD_GENERAL1_SMALL",
                "environmentVariables": [],
            },
            serviceRole=role_arn,
            tags=[{"key": "Name", "value": "test"}],
        )["project"]["arn"]

        from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client",
                new=Codebuild(aws_provider),
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.iam_client",
                new=IAM(aws_provider),
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client.audit_config",
                {"codebuild_github_allowed_organizations": ["allowed-org"]},
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations import (
                codebuild_project_uses_allowed_github_organizations,
            )

            check = codebuild_project_uses_allowed_github_organizations()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == project_name
            assert result[0].resource_arn == project_arn
            assert "which is in the allowed organizations" in result[0].status_extended
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_project_github_not_allowed_organization(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        codebuild_client = client("codebuild", region_name=AWS_REGION_EU_WEST_1)
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        project_name = "test-project-github-not-allowed"
        role_name = "codebuild-test-role"
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument="""{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "codebuild.amazonaws.com"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            }""",
        )["Role"]["Arn"]
        project_arn = codebuild_client.create_project(
            name=project_name,
            source={
                "type": "GITHUB",
                "location": "https://github.com/not-allowed-org/repo",
            },
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:4.0",
                "computeType": "BUILD_GENERAL1_SMALL",
                "environmentVariables": [],
            },
            serviceRole=role_arn,
            tags=[{"key": "Name", "value": "test"}],
        )["project"]["arn"]

        from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client",
                new=Codebuild(aws_provider),
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.iam_client",
                new=IAM(aws_provider),
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client.audit_config",
                {"codebuild_github_allowed_organizations": ["allowed-org"]},
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations import (
                codebuild_project_uses_allowed_github_organizations,
            )

            check = codebuild_project_uses_allowed_github_organizations()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == project_name
            assert result[0].resource_arn == project_arn
            assert (
                "which is not in the allowed organizations" in result[0].status_extended
            )
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_project_github_no_codebuild_trusted_principal(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client",
                new=Codebuild(aws_provider),
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.iam_client",
                new=IAM(aws_provider),
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client.audit_config",
                {"codebuild_github_allowed_organizations": ["allowed-org"]},
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations import (
                codebuild_project_uses_allowed_github_organizations,
            )

            check = codebuild_project_uses_allowed_github_organizations()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_project_github_enterprise_allowed_organization(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        codebuild_client = client("codebuild", region_name=AWS_REGION_EU_WEST_1)
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        project_name = "test-project-github-enterprise-allowed"
        role_name = "codebuild-test-role"
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument="""{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "codebuild.amazonaws.com"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            }""",
        )["Role"]["Arn"]
        project_arn = codebuild_client.create_project(
            name=project_name,
            source={
                "type": "GITHUB_ENTERPRISE",
                "location": "https://github.enterprise.com/allowed-org/repo",
            },
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:4.0",
                "computeType": "BUILD_GENERAL1_SMALL",
                "environmentVariables": [],
            },
            serviceRole=role_arn,
            tags=[{"key": "Name", "value": "test"}],
        )["project"]["arn"]

        from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client",
                new=Codebuild(aws_provider),
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.iam_client",
                new=IAM(aws_provider),
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client.audit_config",
                {"codebuild_github_allowed_organizations": ["allowed-org"]},
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations import (
                codebuild_project_uses_allowed_github_organizations,
            )

            check = codebuild_project_uses_allowed_github_organizations()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == project_name
            assert result[0].resource_arn == project_arn
            assert "which is in the allowed organizations" in result[0].status_extended
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_project_github_enterprise_not_allowed_organization(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        codebuild_client = client("codebuild", region_name=AWS_REGION_EU_WEST_1)
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        project_name = "test-project-github-enterprise-not-allowed"
        role_name = "codebuild-test-role"
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument="""{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "codebuild.amazonaws.com"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            }""",
        )["Role"]["Arn"]
        project_arn = codebuild_client.create_project(
            name=project_name,
            source={
                "type": "GITHUB_ENTERPRISE",
                "location": "https://github.enterprise.com/not-allowed-org/repo",
            },
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:4.0",
                "computeType": "BUILD_GENERAL1_SMALL",
                "environmentVariables": [],
            },
            serviceRole=role_arn,
            tags=[{"key": "Name", "value": "test"}],
        )["project"]["arn"]

        from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client",
                new=Codebuild(aws_provider),
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.iam_client",
                new=IAM(aws_provider),
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client.audit_config",
                {"codebuild_github_allowed_organizations": ["allowed-org"]},
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations import (
                codebuild_project_uses_allowed_github_organizations,
            )

            check = codebuild_project_uses_allowed_github_organizations()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == project_name
            assert result[0].resource_arn == project_arn
            assert (
                "which is not in the allowed organizations" in result[0].status_extended
            )
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_project_github_enterprise_no_codebuild_trusted_principal(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client",
                new=Codebuild(aws_provider),
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.iam_client",
                new=IAM(aws_provider),
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client.audit_config",
                {"codebuild_github_allowed_organizations": ["allowed-org"]},
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations import (
                codebuild_project_uses_allowed_github_organizations,
            )

            check = codebuild_project_uses_allowed_github_organizations()
            result = check.execute()
            assert len(result) == 0
