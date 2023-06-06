from re import search
from unittest import mock

from prowler.providers.aws.services.codebuild.codebuild_service import Project

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_codebuild_project_user_controlled_buildspec:
    def test_project_not_buildspec(self):
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = [
            Project(
                name=project_name,
                arn=project_arn,
                region="eu-west-1",
                last_invoked_time=None,
                buildspec=None,
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
            codebuild_client,
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_user_controlled_buildspec.codebuild_project_user_controlled_buildspec import (
                codebuild_project_user_controlled_buildspec,
            )

            check = codebuild_project_user_controlled_buildspec()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "does not use an user controlled buildspec",
                result[0].status_extended,
            )
            assert result[0].resource_id == project_name
            assert result[0].resource_arn == project_arn

    def test_project_buildspec_not_yaml(self):
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = [
            Project(
                name=project_name,
                arn=project_arn,
                region="eu-west-1",
                last_invoked_time=None,
                buildspec="arn:aws:s3:::my-codebuild-sample2/buildspec.out",
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
            codebuild_client,
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_user_controlled_buildspec.codebuild_project_user_controlled_buildspec import (
                codebuild_project_user_controlled_buildspec,
            )

            check = codebuild_project_user_controlled_buildspec()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "does not use an user controlled buildspec",
                result[0].status_extended,
            )
            assert result[0].resource_id == project_name
            assert result[0].resource_arn == project_arn

    def test_project_valid_buildspec(self):
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = [
            Project(
                name=project_name,
                arn=project_arn,
                region="eu-west-1",
                last_invoked_time=None,
                buildspec="arn:aws:s3:::my-codebuild-sample2/buildspec.yaml",
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
            codebuild_client,
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_user_controlled_buildspec.codebuild_project_user_controlled_buildspec import (
                codebuild_project_user_controlled_buildspec,
            )

            check = codebuild_project_user_controlled_buildspec()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "uses an user controlled buildspec", result[0].status_extended
            )
            assert result[0].resource_id == project_name
            assert result[0].resource_arn == project_arn

    def test_project_invalid_buildspec_without_extension(self):
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = [
            Project(
                name=project_name,
                arn=project_arn,
                region="eu-west-1",
                last_invoked_time=None,
                buildspec="arn:aws:s3:::my-codebuild-sample2/buildspecyaml",
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
            codebuild_client,
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_user_controlled_buildspec.codebuild_project_user_controlled_buildspec import (
                codebuild_project_user_controlled_buildspec,
            )

            check = codebuild_project_user_controlled_buildspec()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "does not use an user controlled buildspec",
                result[0].status_extended,
            )
            assert result[0].resource_id == project_name
            assert result[0].resource_arn == project_arn
