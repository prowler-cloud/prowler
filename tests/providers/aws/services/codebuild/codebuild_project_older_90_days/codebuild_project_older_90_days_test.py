from datetime import datetime, timedelta, timezone
from re import search
from unittest import mock

from prowler.providers.aws.services.codebuild.codebuild_service import CodebuildProject


class Test_codebuild_project_older_90_days:
    def test_project_not_built_in_last_90_days(self):
        codebuild_client = mock.MagicMock
        codebuild_client.projects = [
            CodebuildProject(
                name="test",
                region="eu-west-1",
                last_invoked_time=datetime.now(timezone.utc) - timedelta(days=100),
                buildspec=None,
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
            codebuild_client,
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_older_90_days.codebuild_project_older_90_days import (
                codebuild_project_older_90_days,
            )

            check = codebuild_project_older_90_days()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "has not been invoked in the last 90 days", result[0].status_extended
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == ""

    def test_project_not_built(self):
        codebuild_client = mock.MagicMock
        codebuild_client.projects = [
            CodebuildProject(
                name="test", region="eu-west-1", last_invoked_time=None, buildspec=None
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
            codebuild_client,
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_older_90_days.codebuild_project_older_90_days import (
                codebuild_project_older_90_days,
            )

            check = codebuild_project_older_90_days()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search("has never been built", result[0].status_extended)
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == ""

    def test_project_built_in_last_90_days(self):
        codebuild_client = mock.MagicMock
        codebuild_client.projects = [
            CodebuildProject(
                name="test",
                region="eu-west-1",
                last_invoked_time=datetime.now(timezone.utc) - timedelta(days=10),
                buildspec=None,
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
            codebuild_client,
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_older_90_days.codebuild_project_older_90_days import (
                codebuild_project_older_90_days,
            )

            check = codebuild_project_older_90_days()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "has been invoked in the last 90 days", result[0].status_extended
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == ""
