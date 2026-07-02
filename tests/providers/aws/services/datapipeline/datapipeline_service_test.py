from unittest.mock import patch

import botocore
from moto import mock_aws

from prowler.providers.aws.services.datapipeline.datapipeline_service import (
    DataPipeline,
    Pipeline,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

pipeline_id = "df-1234567890"
pipeline_name = "test-pipeline"
pipeline_arn = (
    f"arn:aws:datapipeline:{AWS_REGION_US_EAST_1}:"
    f"{AWS_ACCOUNT_NUMBER}:pipeline/{pipeline_id}"
)
pipeline_definition = {
    "pipelineObjects": [
        {
            "id": "Default",
            "name": "Default",
            "fields": [{"key": "type", "stringValue": "Default"}],
        }
    ],
    "parameterObjects": [],
    "parameterValues": [],
}

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListPipelines":
        return {"pipelineIdList": [{"id": pipeline_id, "name": pipeline_name}]}
    if operation_name == "GetPipelineDefinition":
        return pipeline_definition
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_US_EAST_1
    )
    regional_client.region = AWS_REGION_US_EAST_1
    return {AWS_REGION_US_EAST_1: regional_client}


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class TestDataPipelineService:
    @mock_aws
    def test_datapipeline_service(self):
        datapipeline = DataPipeline(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert datapipeline.session.__class__.__name__ == "Session"
        assert datapipeline.service == "datapipeline"
        assert len(datapipeline.pipelines) == 1
        assert isinstance(datapipeline.pipelines[pipeline_arn], Pipeline)

        pipeline = datapipeline.pipelines[pipeline_arn]
        assert pipeline.id == pipeline_id
        assert pipeline.name == pipeline_name
        assert pipeline.arn == pipeline_arn
        assert pipeline.region == AWS_REGION_US_EAST_1
        assert pipeline.definition == pipeline_definition
        assert pipeline.tags == []
