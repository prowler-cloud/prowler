from unittest import mock

from prowler.providers.aws.services.datapipeline.datapipeline_service import Pipeline
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_datapipeline_pipeline_no_secrets_in_definition:
    def test_no_pipelines(self):
        datapipeline_client = mock.MagicMock()
        datapipeline_client.pipelines = {}
        datapipeline_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check(datapipeline_client)

        assert len(result) == 0

    def test_pipeline_with_no_secrets_in_definition(self):
        pipeline = _build_pipeline(
            definition={
                "pipelineObjects": [
                    {
                        "id": "Default",
                        "name": "Default",
                        "fields": [
                            {"key": "type", "stringValue": "Default"},
                            {"key": "scheduleType", "stringValue": "cron"},
                        ],
                    }
                ]
            }
        )
        datapipeline_client = mock.MagicMock()
        datapipeline_client.pipelines = {pipeline.arn: pipeline}
        datapipeline_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check(datapipeline_client)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "No secrets found in Data Pipeline test-pipeline definition."
        )
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].resource_id == "df-1234567890"
        assert result[0].resource_arn == pipeline.arn

    def test_pipeline_with_secrets_in_object_field(self):
        pipeline = _build_pipeline(
            definition={
                "pipelineObjects": [
                    {
                        "id": "SqlActivity",
                        "name": "SqlActivity",
                        "fields": [
                            {"key": "type", "stringValue": "SqlActivity"},
                            {
                                "key": "script",
                                "stringValue": "select * from users where token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'",
                            },
                        ],
                    }
                ]
            }
        )
        datapipeline_client = mock.MagicMock()
        datapipeline_client.pipelines = {pipeline.arn: pipeline}
        datapipeline_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check(datapipeline_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "test-pipeline" in result[0].status_extended
        assert "object SqlActivity field script" in result[0].status_extended
        assert "eyJhbGciOiJIUzI1Ni" not in result[0].status_extended
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].resource_id == "df-1234567890"
        assert result[0].resource_arn == pipeline.arn

    def test_pipeline_with_secrets_in_parameter_value(self):
        pipeline = _build_pipeline(
            definition={
                "parameterValues": [
                    {
                        "id": "databasePassword",
                        "stringValue": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXNzd29yZCI6InN1cGVyLXNlY3JldCJ9.zZ7_9wzLQfPy4TAAkpS6I8nRcEvuTnbwN7gGr1pH5fQ",
                    }
                ]
            }
        )
        datapipeline_client = mock.MagicMock()
        datapipeline_client.pipelines = {pipeline.arn: pipeline}
        datapipeline_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check(datapipeline_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "parameter value databasePassword" in result[0].status_extended
        assert "super-secret" not in result[0].status_extended


def _build_pipeline(definition: dict) -> Pipeline:
    pipeline_id = "df-1234567890"
    pipeline_name = "test-pipeline"
    pipeline_arn = (
        f"arn:aws:datapipeline:{AWS_REGION_US_EAST_1}:"
        f"{AWS_ACCOUNT_NUMBER}:pipeline/{pipeline_id}"
    )
    return Pipeline(
        id=pipeline_id,
        name=pipeline_name,
        arn=pipeline_arn,
        region=AWS_REGION_US_EAST_1,
        definition=definition,
    )


def _execute_check(datapipeline_client):
    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(
            "prowler.providers.aws.services.datapipeline.datapipeline_pipeline_no_secrets_in_definition.datapipeline_pipeline_no_secrets_in_definition.datapipeline_client",
            datapipeline_client,
        ),
    ):
        from prowler.providers.aws.services.datapipeline.datapipeline_pipeline_no_secrets_in_definition.datapipeline_pipeline_no_secrets_in_definition import (
            datapipeline_pipeline_no_secrets_in_definition,
        )

        check = datapipeline_pipeline_no_secrets_in_definition()
        return check.execute()
