from unittest import mock

from prowler.providers.aws.services.codebuild.codebuild_service import Project

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_codebuild_bitbucket_urls_no_sensitive_credentials:
    def test_project_no_bitbucket_urls(self):
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = {
            project_arn: Project(
                name=project_name,
                arn=project_arn,
                region="eu-west-1",
                last_invoked_time=None,
                buildspec="",
                bitbucket_urls=[],
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
            codebuild_client,
        ):
            from prowler.providers.aws.services.codebuild.codebuild_bitbucket_urls_no_sensitive_credentials.codebuild_bitbucket_urls_no_sensitive_credentials import (
                codebuild_bitbucket_urls_no_sensitive_credentials,
            )

            check = codebuild_bitbucket_urls_no_sensitive_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CodeBuild project {project_name} does not contain sensitive credentials in Bitbucket repository URLs."
            )
            assert result[0].resource_id == project_name
            assert result[0].resource_arn == project_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION

    def test_project_safe_bitbucket_urls(self):
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = {
            project_arn: Project(
                name=project_name,
                arn=project_arn,
                region="eu-west-1",
                last_invoked_time=None,
                buildspec=None,
                bitbucket_urls=["https://bitbucket.org/exampleuser/my-repo.git"],
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
            codebuild_client,
        ):
            from prowler.providers.aws.services.codebuild.codebuild_bitbucket_urls_no_sensitive_credentials.codebuild_bitbucket_urls_no_sensitive_credentials import (
                codebuild_bitbucket_urls_no_sensitive_credentials,
            )

            check = codebuild_bitbucket_urls_no_sensitive_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CodeBuild project {project_name} does not contain sensitive credentials in Bitbucket repository URLs."
            )
            assert result[0].resource_id == project_name
            assert result[0].resource_arn == project_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION

    def test_project_username_password_bitbucket_urls(self):
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = {
            project_arn: Project(
                name=project_name,
                arn=project_arn,
                region="eu-west-1",
                last_invoked_time=None,
                buildspec="arn:aws:s3:::my-codebuild-sample2/buildspec.yaml",
                bitbucket_urls=[
                    "https://user:pass123@bitbucket.org/exampleuser/my-repo2.git"
                ],
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
            codebuild_client,
        ):
            from prowler.providers.aws.services.codebuild.codebuild_bitbucket_urls_no_sensitive_credentials.codebuild_bitbucket_urls_no_sensitive_credentials import (
                codebuild_bitbucket_urls_no_sensitive_credentials,
            )

            check = codebuild_bitbucket_urls_no_sensitive_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CodeBuild project {project_name} has sensitive credentials in Bitbucket repository URLs: Basic Auth Credentials in URL https://user:pass123@bitbucket.org/exampleuser/my-repo2.git."
            )
            assert result[0].resource_id == project_name
            assert result[0].resource_arn == project_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION

    def test_project_token_bitbucket_urls(self):
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = {
            project_arn: Project(
                name=project_name,
                arn=project_arn,
                region="eu-west-1",
                last_invoked_time=None,
                buildspec="arn:aws:s3:::my-codebuild-sample2/buildspec.yaml",
                bitbucket_urls=[
                    "https://x-token-auth:7saBEbfXpRg-zlO-YQC9Lvh8vtKmdETITD_-GCqYw0ZHbV7ZbMDbUCybDGM4=053EA782@bitbucket.org/testissue4244/test4244.git"
                ],
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
            codebuild_client,
        ):
            from prowler.providers.aws.services.codebuild.codebuild_bitbucket_urls_no_sensitive_credentials.codebuild_bitbucket_urls_no_sensitive_credentials import (
                codebuild_bitbucket_urls_no_sensitive_credentials,
            )

            check = codebuild_bitbucket_urls_no_sensitive_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CodeBuild project {project_name} has sensitive credentials in Bitbucket repository URLs: Token in URL https://x-token-auth:7saBEbfXpRg-zlO-YQC9Lvh8vtKmdETITD_-GCqYw0ZHbV7ZbMDbUCybDGM4=053EA782@bitbucket.org/testissue4244/test4244.git."
            )
            assert result[0].resource_id == project_name
            assert result[0].resource_arn == project_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION
