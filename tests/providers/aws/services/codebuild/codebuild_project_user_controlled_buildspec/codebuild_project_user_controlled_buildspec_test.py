from re import search
from unittest import mock

from prowler.providers.aws.services.codebuild.codebuild_service import CodebuildProject


class Test_codebuild_project_user_controlled_buildspec:
    def test_project_not_buildspec(self):
        codebuild_client = mock.MagicMock
        codebuild_client.projects = [
            CodebuildProject(
                name="test",
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
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == ""

    def test_project_buildspec_not_yaml(self):
        codebuild_client = mock.MagicMock
        codebuild_client.projects = [
            CodebuildProject(
                name="test",
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
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == ""

    def test_project_valid_buildspec(self):
        codebuild_client = mock.MagicMock
        codebuild_client.projects = [
            CodebuildProject(
                name="test",
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
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == ""

    def test_project_invalid_buildspec_without_extension(self):
        codebuild_client = mock.MagicMock
        codebuild_client.projects = [
            CodebuildProject(
                name="test",
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
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == ""
