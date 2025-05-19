from unittest.mock import patch

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild
from prowler.providers.aws.services.iam.iam_service import IAM
from prowler.providers.aws.services.iam.lib import policy
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider


class Test_codebuild_project_uses_allowed_github_organizations:
    def setup_codebuild_iam_mocks(self, audit_config=None):
        """Helper method to set up common mocks"""
        if audit_config is None:
            audit_config = {}

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        codebuild_mock = Codebuild(aws_provider)
        codebuild_mock.audit_config = audit_config

        iam_mock = IAM(aws_provider)

        return aws_provider, codebuild_mock, iam_mock

    def create_codebuild_role(
        self, role_name="codebuild-test-role", service="codebuild.amazonaws.com"
    ):
        """Helper method to create an IAM role"""
        iam_client = client("iam")
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        role = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=str(assume_role_policy_document).replace("'", '"'),
        )
        return role["Role"]["Arn"]

    def create_codebuild_project(
        self, project_name, source_type, source_location, role_arn
    ):
        """Helper method to create a CodeBuild project"""
        codebuild_client = client("codebuild", region_name=AWS_REGION_EU_WEST_1)
        project = codebuild_client.create_project(
            name=project_name,
            source={
                "type": source_type,
                "location": source_location,
            },
            artifacts={
                "type": "NO_ARTIFACTS",
            },
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:4.0",
                "computeType": "BUILD_GENERAL1_SMALL",
            },
            serviceRole=role_arn,
        )
        return project["project"]["arn"]

    @mock_aws
    def test_no_projects(self):
        aws_provider, codebuild_mock, iam_mock = self.setup_codebuild_iam_mocks()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client",
                codebuild_mock,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.iam_client",
                iam_mock,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations import (
                codebuild_project_uses_allowed_github_organizations,
            )

            check = codebuild_project_uses_allowed_github_organizations()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_project_not_github(self):
        role_arn = self.create_codebuild_role()
        project_name = "test-project-not-github"
        self.create_codebuild_project(
            project_name, "S3", "test-bucket/source.zip", role_arn
        )

        aws_provider, codebuild_mock, iam_mock = self.setup_codebuild_iam_mocks()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client",
                codebuild_mock,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.iam_client",
                iam_mock,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations import (
                codebuild_project_uses_allowed_github_organizations,
            )

            check = codebuild_project_uses_allowed_github_organizations()
            result = check.execute()

            # Non-GitHub projects should not be reported
            assert len(result) == 0

    @mock_aws
    def test_project_github_allowed_organization(self):
        role_arn = self.create_codebuild_role()
        project_name = "test-project-github-allowed"
        project_arn = self.create_codebuild_project(
            project_name, "GITHUB", "https://github.com/allowed-org/repo", role_arn
        )

        aws_provider, codebuild_mock, iam_mock = self.setup_codebuild_iam_mocks(
            {"codebuild_github_allowed_organizations": ["allowed-org"]}
        )

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client",
                codebuild_mock,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.iam_client",
                iam_mock,
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
        role_arn = self.create_codebuild_role()
        project_name = "test-project-github-not-allowed"
        project_arn = self.create_codebuild_project(
            project_name, "GITHUB", "https://github.com/not-allowed-org/repo", role_arn
        )

        aws_provider, codebuild_mock, iam_mock = self.setup_codebuild_iam_mocks(
            {"codebuild_github_allowed_organizations": ["allowed-org"]}
        )

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client",
                codebuild_mock,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.iam_client",
                iam_mock,
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
        role_arn = self.create_codebuild_role(
            "lambda-test-role", "lambda.amazonaws.com"
        )
        project_name = "test-project-github-lambda-role"
        project_arn = self.create_codebuild_project(
            project_name, "GITHUB", "https://github.com/not-allowed-org/repo", role_arn
        )

        aws_provider, codebuild_mock, iam_mock = self.setup_codebuild_iam_mocks(
            {"codebuild_github_allowed_organizations": ["allowed-org"]}
        )

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client",
                codebuild_mock,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.iam_client",
                iam_mock,
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
            assert (
                "does not use an IAM role with codebuild.amazonaws.com as a trusted principal"
                in result[0].status_extended
            )
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_project_github_enterprise_allowed_organization(self):
        role_arn = self.create_codebuild_role()
        project_name = "test-project-github-enterprise-allowed"
        project_arn = self.create_codebuild_project(
            project_name,
            "GITHUB_ENTERPRISE",
            "https://github.enterprise.com/allowed-org/repo",
            role_arn,
        )

        aws_provider, codebuild_mock, iam_mock = self.setup_codebuild_iam_mocks(
            {"codebuild_github_allowed_organizations": ["allowed-org"]}
        )

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client",
                codebuild_mock,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.iam_client",
                iam_mock,
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
        role_arn = self.create_codebuild_role()
        project_name = "test-project-github-enterprise-not-allowed"
        project_arn = self.create_codebuild_project(
            project_name,
            "GITHUB_ENTERPRISE",
            "https://github.enterprise.com/not-allowed-org/repo",
            role_arn,
        )

        aws_provider, codebuild_mock, iam_mock = self.setup_codebuild_iam_mocks(
            {"codebuild_github_allowed_organizations": ["allowed-org"]}
        )

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client",
                codebuild_mock,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.iam_client",
                iam_mock,
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
        role_arn = self.create_codebuild_role(
            "lambda-test-role-enterprise", "lambda.amazonaws.com"
        )
        project_name = "test-project-github-enterprise-lambda-role"
        project_arn = self.create_codebuild_project(
            project_name,
            "GITHUB_ENTERPRISE",
            "https://github.enterprise.com/not-allowed-org/repo",
            role_arn,
        )

        aws_provider, codebuild_mock, iam_mock = self.setup_codebuild_iam_mocks(
            {"codebuild_github_allowed_organizations": ["allowed-org"]}
        )

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.codebuild_client",
                codebuild_mock,
            ),
            patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_uses_allowed_github_organizations.codebuild_project_uses_allowed_github_organizations.iam_client",
                iam_mock,
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
            assert (
                "does not use an IAM role with codebuild.amazonaws.com as a trusted principal"
                in result[0].status_extended
            )
            assert result[0].region == AWS_REGION_EU_WEST_1


def test_check_codebuild_trust_and_github_org_allows():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    github_repo_url = "https://github.com/allowed-org/repo"
    allowed_organizations = ["allowed-org"]
    is_allowed, org_name = policy.is_codebuild_using_allowed_github_org(
        trust_policy, github_repo_url, allowed_organizations
    )
    assert is_allowed is True
    assert org_name == "allowed-org"


def test_check_codebuild_trust_and_github_org_denies():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    github_repo_url = "https://github.com/not-allowed-org/repo"
    allowed_organizations = ["allowed-org"]
    is_allowed, org_name = policy.is_codebuild_using_allowed_github_org(
        trust_policy, github_repo_url, allowed_organizations
    )
    assert is_allowed is False
    assert org_name == "not-allowed-org"


def test_check_codebuild_trust_and_github_org_no_codebuild_principal():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    github_repo_url = "https://github.com/allowed-org/repo"
    allowed_organizations = ["allowed-org"]
    is_allowed, org_name = policy.is_codebuild_using_allowed_github_org(
        trust_policy, github_repo_url, allowed_organizations
    )
    assert is_allowed is False
    assert org_name is None


def test_check_codebuild_trust_and_github_org_invalid_url():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    github_repo_url = "https://github.com/"
    allowed_organizations = ["allowed-org"]
    is_allowed, org_name = policy.is_codebuild_using_allowed_github_org(
        trust_policy, github_repo_url, allowed_organizations
    )
    assert is_allowed is False
    assert org_name is None


def test_has_codebuild_trusted_principal_true():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    assert policy.has_codebuild_trusted_principal(trust_policy) is True


def test_has_codebuild_trusted_principal_false():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    assert policy.has_codebuild_trusted_principal(trust_policy) is False


def test_has_codebuild_trusted_principal_empty():
    trust_policy = {}
    assert policy.has_codebuild_trusted_principal(trust_policy) is False
