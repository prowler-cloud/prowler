from unittest.mock import patch

import botocore
from moto import mock_aws

from prowler.providers.aws.services.codepipeline.codepipeline_service import (
    CodePipeline,
    Pipeline,
    Source,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_COMMERCIAL_PARTITION,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

pipeline_name = "test-pipeline"
pipeline_arn = f"arn:{AWS_COMMERCIAL_PARTITION}:codepipeline:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:pipeline/{pipeline_name}"
source_type = "CodeStarSourceConnection"
repository_id = "prowler-cloud/prowler-private"
connection_arn = f"arn:{AWS_COMMERCIAL_PARTITION}:codestar-connections:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:connection/test"

# Mocking API calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListPipelines":
        return {"pipelines": [{"name": pipeline_name}]}
    elif operation_name == "GetPipeline":
        return {
            "pipeline": {
                "name": pipeline_name,
                "stages": [
                    {
                        "name": "Source",
                        "actions": [
                            {
                                "name": "Source",
                                "actionTypeId": {
                                    "category": "Source",
                                    "owner": "AWS",
                                    "provider": source_type,
                                    "version": "1",
                                },
                                "configuration": {
                                    "ConnectionArn": connection_arn,
                                    "FullRepositoryId": repository_id,
                                },
                            }
                        ],
                    }
                ],
            },
        }
    elif operation_name == "ListTagsForResource":
        return {
            "tags": [{"key": "Environment", "value": "Test"}]
        }  # Key/Value -> key/value
    return make_api_call(self, operation_name, kwarg)


# Mock generate_regional_clients()
def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


class Test_CodePipeline_Service:
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    @mock_aws
    def test_codepipeline_service(self):
        codepipeline = CodePipeline(set_mocked_aws_provider())

        assert codepipeline.session.__class__.__name__ == "Session"
        assert codepipeline.service == "codepipeline"

        # Test pipeline properties
        assert len(codepipeline.pipelines) == 1
        assert isinstance(codepipeline.pipelines, dict)
        assert isinstance(codepipeline.pipelines[pipeline_arn], Pipeline)

        pipeline = codepipeline.pipelines[pipeline_arn]
        assert pipeline.name == pipeline_name
        assert pipeline.arn == pipeline_arn
        assert pipeline.region == AWS_REGION_EU_WEST_1

        # Test source properties
        assert isinstance(pipeline.source, Source)
        assert pipeline.source.type == source_type
        assert pipeline.source.location == repository_id
        assert pipeline.source.configuration == {
            "ConnectionArn": connection_arn,
            "FullRepositoryId": repository_id,
        }

        # Test tags
        assert pipeline.tags[0]["key"] == "Environment"
        assert pipeline.tags[0]["value"] == "Test"

        # Test status extended
        expected_status = f"CodePipeline {pipeline_name} source repository prowler-cloud/prowler-private is private."
        assert pipeline.status_extended == expected_status
