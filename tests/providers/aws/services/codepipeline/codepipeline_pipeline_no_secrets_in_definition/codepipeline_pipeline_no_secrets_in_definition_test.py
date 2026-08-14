from unittest import mock

from prowler.lib.utils.utils import SecretsScanError
from prowler.providers.aws.services.codepipeline.codepipeline_service import Pipeline
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_codepipeline_pipeline_no_secrets_in_definition:
    def test_no_pipelines(self):
        codepipeline_client = mock.MagicMock()
        codepipeline_client.pipelines = {}
        codepipeline_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check(codepipeline_client)

        assert len(result) == 0

    def test_pipeline_with_no_secrets_in_definition(self):
        pipeline = _build_pipeline(
            definition=[
                {
                    "name": "Source",
                    "actions": [
                        {
                            "name": "SourceAction",
                            "actionTypeId": {
                                "category": "Source",
                                "owner": "AWS",
                                "provider": "CodeStarSourceConnection",
                                "version": "1",
                            },
                            "configuration": {
                                "ConnectionArn": "arn:aws:codestar-connections:us-east-1:123456789012:connection/test",
                                "FullRepositoryId": "myorg/myrepo",
                                "BranchName": "main",
                            },
                        }
                    ],
                }
            ]
        )
        codepipeline_client = mock.MagicMock()
        codepipeline_client.pipelines = {pipeline.arn: pipeline}
        codepipeline_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check(codepipeline_client)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "No secrets found in CodePipeline test-pipeline definition."
        )
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].resource_id == "test-pipeline"
        assert result[0].resource_arn == pipeline.arn

    def test_pipeline_with_secrets_in_action_configuration(self):
        pipeline = _build_pipeline(
            definition=[
                {
                    "name": "Build",
                    "actions": [
                        {
                            "name": "BuildAction",
                            "actionTypeId": {
                                "category": "Build",
                                "owner": "AWS",
                                "provider": "CodeBuild",
                                "version": "1",
                            },
                            "configuration": {
                                "ProjectName": "my-project",
                                "EnvironmentVariables": '[{"name":"API_TOKEN","value":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U","type":"PLAINTEXT"}]',
                            },
                        }
                    ],
                }
            ]
        )
        codepipeline_client = mock.MagicMock()
        codepipeline_client.pipelines = {pipeline.arn: pipeline}
        codepipeline_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check(codepipeline_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "test-pipeline" in result[0].status_extended
        assert "BuildAction" in result[0].status_extended
        assert (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            not in result[0].status_extended
        )
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].resource_id == "test-pipeline"
        assert result[0].resource_arn == pipeline.arn

    def test_pipeline_with_verified_secret_escalates_severity(self):
        from prowler.lib.check.models import Severity

        pipeline = _build_pipeline(
            definition=[
                {
                    "name": "Deploy",
                    "actions": [
                        {
                            "name": "DeployAction",
                            "configuration": {
                                "SecretKey": "verified-secret-value",
                            },
                        }
                    ],
                }
            ]
        )
        codepipeline_client = mock.MagicMock()
        codepipeline_client.pipelines = {pipeline.arn: pipeline}
        codepipeline_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": True,
        }

        result, scan_batch = _execute_check_with_mocked_scan(
            codepipeline_client,
            return_value={
                0: [
                    {
                        "type": "Secret Keyword",
                        "line_number": 1,
                        "filename": "data",
                        "hashed_secret": "x",
                        "is_verified": True,
                    }
                ]
            },
        )

        assert scan_batch.call_args.kwargs.get("validate") is True
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].check_metadata.Severity == Severity.critical
        assert "confirmed to be live" in result[0].status_extended

    def test_scan_error_marks_all_scannable_pipelines_manual(self):
        first_pipeline = _build_pipeline(
            pipeline_name="first-pipeline",
            definition=[
                {
                    "name": "Source",
                    "actions": [
                        {
                            "name": "SourceAction",
                            "configuration": {"BranchName": "main"},
                        }
                    ],
                }
            ],
        )
        second_pipeline = _build_pipeline(
            pipeline_name="second-pipeline",
            definition=[
                {
                    "name": "Build",
                    "actions": [
                        {
                            "name": "BuildAction",
                            "configuration": {"Password": "secret-value"},
                        }
                    ],
                }
            ],
        )
        codepipeline_client = mock.MagicMock()
        codepipeline_client.pipelines = {
            first_pipeline.arn: first_pipeline,
            second_pipeline.arn: second_pipeline,
        }
        codepipeline_client.audit_config = {"secrets_ignore_patterns": []}

        result, scan_batch = _execute_check_with_mocked_scan(
            codepipeline_client,
            side_effect=SecretsScanError("scanner unavailable"),
        )

        scan_payloads = scan_batch.call_args.args[0]
        assert len(scan_payloads) == 2
        assert len(result) == 2
        assert {report.status for report in result} == {"MANUAL"}
        assert all(
            "manual review is required" in report.status_extended for report in result
        )

    def test_pipeline_with_empty_definition_passes(self):
        pipeline = _build_pipeline(definition=[])
        codepipeline_client = mock.MagicMock()
        codepipeline_client.pipelines = {pipeline.arn: pipeline}
        codepipeline_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check(codepipeline_client)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "No secrets found in CodePipeline test-pipeline definition."
        )


def _build_pipeline(
    definition: list,
    pipeline_name: str = "test-pipeline",
) -> Pipeline:
    pipeline_arn = f"arn:aws:codepipeline:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:{pipeline_name}"
    return Pipeline(
        name=pipeline_name,
        arn=pipeline_arn,
        region=AWS_REGION_US_EAST_1,
        definition=definition,
    )


def _execute_check(codepipeline_client):
    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(
            "prowler.providers.aws.services.codepipeline.codepipeline_pipeline_no_secrets_in_definition.codepipeline_pipeline_no_secrets_in_definition.codepipeline_client",
            codepipeline_client,
        ),
    ):
        from prowler.providers.aws.services.codepipeline.codepipeline_pipeline_no_secrets_in_definition.codepipeline_pipeline_no_secrets_in_definition import (
            codepipeline_pipeline_no_secrets_in_definition,
        )

        check = codepipeline_pipeline_no_secrets_in_definition()
        return check.execute()


def _execute_check_with_mocked_scan(
    codepipeline_client, return_value=None, side_effect=None
):
    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(
            "prowler.providers.aws.services.codepipeline.codepipeline_pipeline_no_secrets_in_definition.codepipeline_pipeline_no_secrets_in_definition.codepipeline_client",
            codepipeline_client,
        ),
    ):
        import prowler.providers.aws.services.codepipeline.codepipeline_pipeline_no_secrets_in_definition.codepipeline_pipeline_no_secrets_in_definition as check_module

        with mock.patch.object(
            check_module,
            "detect_secrets_scan_batch",
            return_value=return_value,
            side_effect=side_effect,
        ) as scan_batch:
            check = check_module.codepipeline_pipeline_no_secrets_in_definition()
            return check.execute(), scan_batch
