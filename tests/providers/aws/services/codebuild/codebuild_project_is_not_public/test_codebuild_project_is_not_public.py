from unittest import mock

import pytest

from prowler.providers.aws.services.codebuild.codebuild_service import Source, Project, s3Logs, CloudWatchLogs


class TestCodebuildProjectVisibility:

    @pytest.mark.parametrize("project_visibility, expected_status", [
        ("PUBLIC_READ", "FAILED"),
        ("PRIVATE", "PASS"),
    ])
    def test_codebuild_project_visibility_checks(self, project_visibility, expected_status) -> None:
        codebuild_client = mock.MagicMock

        project_name = "test-visibility-project01"
        project_arn = f'arn:aws:codebuild:eu-west-2:123456789012:project/{project_name}'
        codebuild_client.projects = {
            project_arn: Project(
                name=project_name,
                arn=project_arn,
                region="eu-west-1",
                last_invoked_time=None,
                buildspec="arn:aws:s3:::my-codebuild-sample2/buildspec.yaml",
                source=Source(
                    type='GITHUB',
                    location='https://github.com/example/example'
                ),
                secondary_sources=[],
                tags=[],
                project_visibility=project_visibility,
                environment_variables=[],
                s3_logs=s3Logs(
                    enabled=False,
                    bucket_location='',
                    encrypted=True
                ),
                cloudwatch_logs=CloudWatchLogs(
                    enabled=False,
                    group_name='',
                    stream_name=''
                ),
            )
        }
        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_source_repo_url_no_sensitive_credentials.codebuild_project_source_repo_url_no_sensitive_credentials.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_is_not_public.codebuild_project_is_not_public import \
                codebuild_project_is_not_public

            check = codebuild_project_is_not_public()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_arn == project_arn
            assert result[0].status == expected_status
