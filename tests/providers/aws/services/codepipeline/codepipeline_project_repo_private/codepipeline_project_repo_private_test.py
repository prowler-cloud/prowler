import urllib.error
import urllib.request
from unittest import mock

from prowler.providers.aws.services.codepipeline.codepipeline_service import (
    Pipeline,
    Source,
)
from tests.providers.aws.utils import set_mocked_aws_provider

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_codepipeline_project_repo_private:
    """Tests for AWS CodePipeline repository privacy checks.
    This module contains test cases to verify the functionality of checking
    whether CodePipeline source repositories are private or public.
    """

    def test_pipeline_private_repo(self):
        """Test detection of private repository in CodePipeline.
        Tests that the check correctly identifies a private repository
        when both GitHub and GitLab return 404.
        """
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION]),
        ):
            codepipeline_client = mock.MagicMock
            pipeline_name = "test-pipeline"
            pipeline_arn = f"arn:aws:codepipeline:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:pipeline/{pipeline_name}"
            connection_arn = f"arn:aws:codestar-connections:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:connection/test-connection"
            repo_id = "prowler-cloud/prowler-private"

            codepipeline_client.pipelines = {
                pipeline_arn: Pipeline(
                    name=pipeline_name,
                    arn=pipeline_arn,
                    region=AWS_REGION,
                    source=Source(
                        type="CodeStarSourceConnection",
                        repository_id=repo_id,
                        configuration={
                            "FullRepositoryId": repo_id,
                            "ConnectionArn": connection_arn,
                        },
                    ),
                    tags=[],
                )
            }

            with (
                mock.patch(
                    "prowler.providers.aws.services.codepipeline.codepipeline_service.CodePipeline",
                    codepipeline_client,
                ),
                mock.patch(
                    "prowler.providers.aws.services.codepipeline.codepipeline_project_repo_private.codepipeline_project_repo_private.codepipeline_client",
                    codepipeline_client,
                ),
                mock.patch("boto3.client") as mock_client,
                mock.patch("urllib.request.urlopen") as mock_urlopen,
            ):
                mock_connection = mock_client.return_value
                mock_connection.get_connection.return_value = {
                    "Connection": {"ProviderType": "GitHub"}
                }

                def mock_urlopen_side_effect(req, context=None):
                    raise urllib.error.HTTPError(
                        url="", code=404, msg="", hdrs={}, fp=None
                    )

                mock_urlopen.side_effect = mock_urlopen_side_effect

                from prowler.providers.aws.services.codepipeline.codepipeline_project_repo_private.codepipeline_project_repo_private import (
                    codepipeline_project_repo_private,
                )

                check = codepipeline_project_repo_private()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"CodePipeline {pipeline_name} source repository {repo_id} is private."
                )
                assert result[0].resource_id == pipeline_name
                assert result[0].resource_arn == pipeline_arn
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION

    def test_pipeline_public_github_repo(self):
        """Test detection of public GitHub repository in CodePipeline.
        Tests that the check correctly identifies a public GitHub repository
        when GitHub returns 200.
        """
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION]),
        ):
            codepipeline_client = mock.MagicMock
            pipeline_name = "test-pipeline"
            pipeline_arn = f"arn:aws:codepipeline:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:pipeline/{pipeline_name}"
            connection_arn = f"arn:aws:codestar-connections:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:connection/test-connection"
            repo_id = "prowler-cloud/prowler"

            codepipeline_client.pipelines = {
                pipeline_arn: Pipeline(
                    name=pipeline_name,
                    arn=pipeline_arn,
                    region=AWS_REGION,
                    source=Source(
                        type="CodeStarSourceConnection",
                        repository_id=repo_id,
                        configuration={
                            "FullRepositoryId": repo_id,
                            "ConnectionArn": connection_arn,
                        },
                    ),
                    tags=[],
                )
            }

            with (
                mock.patch(
                    "prowler.providers.aws.services.codepipeline.codepipeline_service.CodePipeline",
                    codepipeline_client,
                ),
                mock.patch(
                    "prowler.providers.aws.services.codepipeline.codepipeline_project_repo_private.codepipeline_project_repo_private.codepipeline_client",
                    codepipeline_client,
                ),
                mock.patch("boto3.client") as mock_client,
                mock.patch("urllib.request.urlopen") as mock_urlopen,
            ):
                mock_connection = mock_client.return_value
                mock_connection.get_connection.return_value = {
                    "Connection": {"ProviderType": "GitHub"}
                }

                mock_response = mock.MagicMock()
                mock_response.getcode.return_value = 200
                mock_response.geturl.return_value = f"https://github.com/{repo_id}"

                def mock_urlopen_side_effect(req, context=None):
                    if "github.com" in req.get_full_url():
                        return mock_response
                    raise urllib.error.HTTPError(
                        url="", code=404, msg="", hdrs={}, fp=None
                    )

                mock_urlopen.side_effect = mock_urlopen_side_effect

                from prowler.providers.aws.services.codepipeline.codepipeline_project_repo_private.codepipeline_project_repo_private import (
                    codepipeline_project_repo_private,
                )

                check = codepipeline_project_repo_private()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"CodePipeline {pipeline_name} source repository is public: https://github.com/{repo_id}"
                )
                assert result[0].resource_id == pipeline_name
                assert result[0].resource_arn == pipeline_arn
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION

    def test_pipeline_public_gitlab_repo(self):
        """Test detection of public GitLab repository in CodePipeline.
        Tests that the check correctly identifies a public GitLab repository
        when GitLab returns 200 without sign_in redirect.
        """
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION]),
        ):
            codepipeline_client = mock.MagicMock
            pipeline_name = "test-pipeline"
            pipeline_arn = f"arn:aws:codepipeline:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:pipeline/{pipeline_name}"
            connection_arn = f"arn:aws:codestar-connections:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:connection/test-connection"
            repo_id = "prowler-cloud/prowler-private"

            codepipeline_client.pipelines = {
                pipeline_arn: Pipeline(
                    name=pipeline_name,
                    arn=pipeline_arn,
                    region=AWS_REGION,
                    source=Source(
                        type="CodeStarSourceConnection",
                        repository_id=repo_id,
                        configuration={
                            "FullRepositoryId": repo_id,
                            "ConnectionArn": connection_arn,
                        },
                    ),
                    tags=[],
                )
            }

            with (
                mock.patch(
                    "prowler.providers.aws.services.codepipeline.codepipeline_service.CodePipeline",
                    codepipeline_client,
                ),
                mock.patch(
                    "prowler.providers.aws.services.codepipeline.codepipeline_project_repo_private.codepipeline_project_repo_private.codepipeline_client",
                    codepipeline_client,
                ),
                mock.patch("boto3.client") as mock_client,
                mock.patch("urllib.request.urlopen") as mock_urlopen,
            ):
                mock_connection = mock_client.return_value
                mock_connection.get_connection.return_value = {
                    "Connection": {"ProviderType": "GitLab"}
                }

                mock_response = mock.MagicMock()
                mock_response.getcode.return_value = 200
                mock_response.geturl.return_value = f"https://gitlab.com/{repo_id}"

                def mock_urlopen_side_effect(req, context=None):
                    if "gitlab.com" in req.get_full_url():
                        return mock_response
                    raise urllib.error.HTTPError(
                        url="", code=404, msg="", hdrs={}, fp=None
                    )

                mock_urlopen.side_effect = mock_urlopen_side_effect

                from prowler.providers.aws.services.codepipeline.codepipeline_project_repo_private.codepipeline_project_repo_private import (
                    codepipeline_project_repo_private,
                )

                check = codepipeline_project_repo_private()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"CodePipeline {pipeline_name} source repository is public: https://gitlab.com/{repo_id}"
                )
                assert result[0].resource_id == pipeline_name
                assert result[0].resource_arn == pipeline_arn
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION
