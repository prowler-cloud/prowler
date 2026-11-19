from unittest import mock

from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

AWS_COMMERCIAL_PARTITION = "aws"

pipeline_name = "test-pipeline"
pipeline_arn = f"arn:{AWS_COMMERCIAL_PARTITION}:codepipeline:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{pipeline_name}"

# Import the check class once at module level under a controlled patch so that
# codepipeline_client.py (which calls CodePipeline(provider) at import time) is
# never imported without a mock in place.  This avoids the Python 3.12
# pkgutil.resolve_name AttributeError that occurs when mock.patch tries to
# resolve the dotted path inside __enter__ and triggers a bare import.
with mock.patch(
    "prowler.providers.aws.services.codepipeline.codepipeline_service.CodePipeline"
):
    import prowler.providers.aws.services.codepipeline.codepipeline_pipeline_no_secrets_in_definition.codepipeline_pipeline_no_secrets_in_definition as check_module
    from prowler.providers.aws.services.codepipeline.codepipeline_pipeline_no_secrets_in_definition.codepipeline_pipeline_no_secrets_in_definition import (
        codepipeline_pipeline_no_secrets_in_definition,
    )


class Test_codepipeline_pipeline_no_secrets_in_definition:
    def test_no_pipelines(self):
        """No findings are returned when there are no pipelines."""
        codepipeline_client = mock.MagicMock()
        codepipeline_client.pipelines = {}
        codepipeline_client.audit_config = {"secrets_ignore_patterns": []}

        with mock.patch.object(check_module, "codepipeline_client", codepipeline_client):
            check = codepipeline_pipeline_no_secrets_in_definition()
            result = check.execute()

            assert len(result) == 0

    def test_pipeline_no_stages(self):
        """A pipeline with no stages passes the check."""
        from prowler.providers.aws.services.codepipeline.codepipeline_service import (
            Pipeline,
        )

        codepipeline_client = mock.MagicMock()
        codepipeline_client.pipelines = {
            pipeline_arn: Pipeline(
                name=pipeline_name,
                arn=pipeline_arn,
                region=AWS_REGION_EU_WEST_1,
            )
        }
        codepipeline_client.audit_config = {"secrets_ignore_patterns": []}

        with mock.patch.object(check_module, "codepipeline_client", codepipeline_client):
            check = codepipeline_pipeline_no_secrets_in_definition()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CodePipeline pipeline {pipeline_name} does not have secrets in its definition."
            )
            assert result[0].resource_id == pipeline_name
            assert result[0].resource_arn == pipeline_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_pipeline_no_secrets(self):
        """A pipeline with stages but no sensitive values passes the check."""
        from prowler.providers.aws.services.codepipeline.codepipeline_service import (
            Pipeline,
            PipelineAction,
            PipelineStage,
        )

        codepipeline_client = mock.MagicMock()
        codepipeline_client.pipelines = {
            pipeline_arn: Pipeline(
                name=pipeline_name,
                arn=pipeline_arn,
                region=AWS_REGION_EU_WEST_1,
                stages=[
                    PipelineStage(
                        name="Source",
                        actions=[
                            PipelineAction(
                                name="SourceAction",
                                configuration={
                                    "BranchName": "main",
                                    "FullRepositoryId": "myorg/myrepo",
                                },
                            )
                        ],
                    ),
                    PipelineStage(
                        name="Build",
                        actions=[
                            PipelineAction(
                                name="BuildAction",
                                configuration={"ProjectName": "my-codebuild-project"},
                            )
                        ],
                    ),
                ],
            )
        }
        codepipeline_client.audit_config = {"secrets_ignore_patterns": []}

        with mock.patch.object(check_module, "codepipeline_client", codepipeline_client):
            check = codepipeline_pipeline_no_secrets_in_definition()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CodePipeline pipeline {pipeline_name} does not have secrets in its definition."
            )
            assert result[0].resource_id == pipeline_name
            assert result[0].resource_arn == pipeline_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_pipeline_with_secrets(self):
        """A pipeline with a hardcoded AWS access key in action configuration fails the check."""
        from prowler.providers.aws.services.codepipeline.codepipeline_service import (
            Pipeline,
            PipelineAction,
            PipelineStage,
        )

        codepipeline_client = mock.MagicMock()
        codepipeline_client.pipelines = {
            pipeline_arn: Pipeline(
                name=pipeline_name,
                arn=pipeline_arn,
                region=AWS_REGION_EU_WEST_1,
                stages=[
                    PipelineStage(
                        name="Source",
                        actions=[
                            PipelineAction(
                                name="SourceAction",
                                configuration={
                                    "BranchName": "main",
                                    "FullRepositoryId": "myorg/myrepo",
                                },
                            )
                        ],
                    ),
                    PipelineStage(
                        name="Deploy",
                        actions=[
                            PipelineAction(
                                name="DeployAction",
                                configuration={
                                    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                                },
                            )
                        ],
                    ),
                ],
            )
        }
        codepipeline_client.audit_config = {"secrets_ignore_patterns": []}

        with mock.patch.object(check_module, "codepipeline_client", codepipeline_client):
            check = codepipeline_pipeline_no_secrets_in_definition()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Deploy" in result[0].status_extended
            assert "DeployAction" in result[0].status_extended
            assert result[0].resource_id == pipeline_name
            assert result[0].resource_arn == pipeline_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_pipeline_action_no_configuration(self):
        """A pipeline where an action has no configuration passes the check."""
        from prowler.providers.aws.services.codepipeline.codepipeline_service import (
            Pipeline,
            PipelineAction,
            PipelineStage,
        )

        codepipeline_client = mock.MagicMock()
        codepipeline_client.pipelines = {
            pipeline_arn: Pipeline(
                name=pipeline_name,
                arn=pipeline_arn,
                region=AWS_REGION_EU_WEST_1,
                stages=[
                    PipelineStage(
                        name="Approval",
                        actions=[
                            PipelineAction(
                                name="ManualApproval",
                                configuration=None,
                            )
                        ],
                    ),
                ],
            )
        }
        codepipeline_client.audit_config = {"secrets_ignore_patterns": []}

        with mock.patch.object(check_module, "codepipeline_client", codepipeline_client):
            check = codepipeline_pipeline_no_secrets_in_definition()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CodePipeline pipeline {pipeline_name} does not have secrets in its definition."
            )
