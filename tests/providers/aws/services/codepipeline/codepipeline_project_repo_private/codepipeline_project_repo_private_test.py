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
        """Test detection of private GitHub repository in CodePipeline.

        Tests that the check correctly identifies a private GitHub repository
        when HTTP 404 response is received.

        Returns:
            None
        """

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION]),
        ):
            codepipeline_client = mock.MagicMock
            pipeline_name = "test-pipeline"
            pipeline_arn = f"arn:aws:codepipeline:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:pipeline/{pipeline_name}"
            connection_arn = f"arn:aws:codestar-connections:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:connection/test-connection"

            codepipeline_client.pipelines = {
                pipeline_arn: Pipeline(
                    name=pipeline_name,
                    arn=pipeline_arn,
                    region=AWS_REGION,
                    source=Source(
                        type="CodeStarSourceConnection",
                        location="prowler-cloud/prowler",
                        configuration={
                            "FullRepositoryId": "prowler-cloud/prowler",
                            "ConnectionArn": connection_arn,
                        },
                    ),
                    tags=[],
                )
            }

            with mock.patch(
                "prowler.providers.aws.services.codepipeline.codepipeline_service.CodePipeline",
                codepipeline_client,
            ), mock.patch(
                "prowler.providers.aws.services.codepipeline.codepipeline_project_repo_private.codepipeline_project_repo_private.codepipeline_client",
                codepipeline_client,
            ), mock.patch(
                "boto3.client"
            ) as mock_client, mock.patch(
                "urllib.request.urlopen"
            ) as mock_urlopen:
                mock_connection = mock_client.return_value
                mock_connection.get_connection.return_value = {
                    "Connection": {"ProviderType": "GitHub"}
                }

                # Mock URL check response for private repo
                mock_response = mock.MagicMock()
                mock_response.getcode.return_value = 404
                mock_urlopen.side_effect = urllib.error.HTTPError(
                    url="", code=404, msg="", hdrs={}, fp=None
                )

                from prowler.providers.aws.services.codepipeline.codepipeline_project_repo_private.codepipeline_project_repo_private import (
                    codepipeline_project_repo_private,
                )

                check = codepipeline_project_repo_private()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"CodePipeline {pipeline_name} source repository is private: https://github.com/prowler-cloud/prowler"
                )

    def test_pipeline_public_repo(self):
        """Test detection of public GitHub repository in CodePipeline.

        Tests that the check correctly identifies a public GitHub repository
        when HTTP 200 response is received.

        Returns:
            None
        """

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION]),
        ):
            codepipeline_client = mock.MagicMock
            pipeline_name = "test-pipeline"
            pipeline_arn = f"arn:aws:codepipeline:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:pipeline/{pipeline_name}"
            connection_arn = f"arn:aws:codestar-connections:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:connection/test-connection"

            codepipeline_client.pipelines = {
                pipeline_arn: Pipeline(
                    name=pipeline_name,
                    arn=pipeline_arn,
                    region=AWS_REGION,
                    source=Source(
                        type="CodeStarSourceConnection",
                        location="prowler-cloud/prowler",
                        configuration={
                            "FullRepositoryId": "prowler-cloud/prowler",
                            "ConnectionArn": connection_arn,
                        },
                    ),
                    tags=[],
                )
            }

            with mock.patch(
                "prowler.providers.aws.services.codepipeline.codepipeline_service.CodePipeline",
                codepipeline_client,
            ), mock.patch(
                "prowler.providers.aws.services.codepipeline.codepipeline_project_repo_private.codepipeline_project_repo_private.codepipeline_client",
                codepipeline_client,
            ), mock.patch(
                "boto3.client"
            ) as mock_client, mock.patch(
                "urllib.request.urlopen"
            ) as mock_urlopen:
                mock_connection = mock_client.return_value
                mock_connection.get_connection.return_value = {
                    "Connection": {"ProviderType": "GitHub"}
                }

                # Mock URL check response for public repo
                mock_response = mock.MagicMock()
                mock_response.getcode.return_value = 200
                mock_response.geturl.return_value = (
                    "https://github.com/prowler-cloud/prowler"
                )
                mock_urlopen.return_value = mock_response

                from prowler.providers.aws.services.codepipeline.codepipeline_project_repo_private.codepipeline_project_repo_private import (
                    codepipeline_project_repo_private,
                )

                check = codepipeline_project_repo_private()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"CodePipeline {pipeline_name} source repository is public: https://github.com/prowler-cloud/prowler"
                )

    def test_pipeline_private_gitlab_repo(self):
        """Test detection of private GitLab repository in CodePipeline.

        Tests that the check correctly identifies a private GitLab repository
        when redirected to sign-in page.

        Returns:
            None

        Note:
            GitLab returns 200 but redirects to sign-in page for private repos.
        """

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION]),
        ):
            codepipeline_client = mock.MagicMock
            pipeline_name = "test-pipeline"
            pipeline_arn = f"arn:aws:codepipeline:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:pipeline/{pipeline_name}"
            connection_arn = f"arn:aws:codestar-connections:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:connection/test-connection"

            codepipeline_client.pipelines = {
                pipeline_arn: Pipeline(
                    name=pipeline_name,
                    arn=pipeline_arn,
                    region=AWS_REGION,
                    source=Source(
                        type="CodeStarSourceConnection",
                        location="test/repo",
                        configuration={
                            "FullRepositoryId": "prowler-cloud/prowler-private",
                            "ConnectionArn": connection_arn,
                        },
                    ),
                    tags=[],
                )
            }

            with mock.patch(
                "prowler.providers.aws.services.codepipeline.codepipeline_service.CodePipeline",
                codepipeline_client,
            ), mock.patch(
                "prowler.providers.aws.services.codepipeline.codepipeline_project_repo_private.codepipeline_project_repo_private.codepipeline_client",
                codepipeline_client,
            ), mock.patch(
                "boto3.client"
            ) as mock_client, mock.patch(
                "urllib.request.urlopen"
            ) as mock_urlopen:
                mock_connection = mock_client.return_value
                mock_connection.get_connection.return_value = {
                    "Connection": {"ProviderType": "GitLab"}
                }

                # Mock URL check response for private repo
                mock_response = mock.MagicMock()
                mock_response.getcode.return_value = 200
                mock_response.geturl.return_value = "https://gitlab.com/sign_in"
                mock_urlopen.return_value = mock_response

                from prowler.providers.aws.services.codepipeline.codepipeline_project_repo_private.codepipeline_project_repo_private import (
                    codepipeline_project_repo_private,
                )

                check = codepipeline_project_repo_private()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"CodePipeline {pipeline_name} source repository is private: https://gitlab.com/prowler-cloud/prowler-private"
                )
                assert result[0].resource_id == pipeline_name
                assert result[0].resource_arn == pipeline_arn
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION

    def test_pipeline_public_gitlab_repo(self):
        """Test detection of public GitLab repository in CodePipeline.

        Tests that the check correctly identifies a public GitLab repository
        when direct access is possible.

        Returns:
            None

        Note:
            GitLab returns 200 with direct repo access for public repos.
        """
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION]),
        ):
            codepipeline_client = mock.MagicMock
            pipeline_name = "test-pipeline"
            pipeline_arn = f"arn:aws:codepipeline:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:pipeline/{pipeline_name}"
            connection_arn = f"arn:aws:codestar-connections:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:connection/test-connection"

            codepipeline_client.pipelines = {
                pipeline_arn: Pipeline(
                    name=pipeline_name,
                    arn=pipeline_arn,
                    region=AWS_REGION,
                    source=Source(
                        type="CodeStarSourceConnection",
                        location="prowler-cloud/prowler-private",
                        configuration={
                            "FullRepositoryId": "prowler-cloud/prowler-private",
                            "ConnectionArn": connection_arn,
                        },
                    ),
                    tags=[],
                )
            }

            with mock.patch(
                "prowler.providers.aws.services.codepipeline.codepipeline_service.CodePipeline",
                codepipeline_client,
            ), mock.patch(
                "prowler.providers.aws.services.codepipeline.codepipeline_project_repo_private.codepipeline_project_repo_private.codepipeline_client",
                codepipeline_client,
            ), mock.patch(
                "boto3.client"
            ) as mock_client, mock.patch(
                "urllib.request.urlopen"
            ) as mock_urlopen:
                mock_connection = mock_client.return_value
                mock_connection.get_connection.return_value = {
                    "Connection": {"ProviderType": "GitLab"}
                }

                # Mock URL check response for public repo
                mock_response = mock.MagicMock()
                mock_response.getcode.return_value = 200
                mock_response.geturl.return_value = "https://gitlab.com/test/repo"
                mock_urlopen.return_value = mock_response

                from prowler.providers.aws.services.codepipeline.codepipeline_project_repo_private.codepipeline_project_repo_private import (
                    codepipeline_project_repo_private,
                )

                check = codepipeline_project_repo_private()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"CodePipeline {pipeline_name} source repository is public: https://gitlab.com/prowler-cloud/prowler-private"
                )
                assert result[0].resource_id == pipeline_name
                assert result[0].resource_arn == pipeline_arn
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION
