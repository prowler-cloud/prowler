from unittest.mock import patch

import botocore
from moto import mock_aws

from prowler.providers.aws.services.batch.batch_service import (
    Batch,
    JobDefinition,
    JobDefinitionContainer,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

jd_name = "test-job-def"
jd_arn = f"arn:aws:batch:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:job-definition/{jd_name}:1"
jd_revision = 1
jd_tags = {"tag_key": "tag_val"}

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeJobDefinitions":
        return {
            "jobDefinitions": [
                {
                    "jobDefinitionName": jd_name,
                    "jobDefinitionArn": jd_arn,
                    "revision": jd_revision,
                    "status": "ACTIVE",
                    "type": "container",
                    "containerProperties": {
                        "image": "ubuntu",
                        "command": ["echo", "hello"],
                        "environment": [{"name": "env_key", "value": "env_val"}],
                    },
                    "nodeProperties": {
                        "numNodes": 2,
                        "mainNode": 0,
                        "nodeRangeProperties": [
                            {
                                "targetNodes": "0:",
                                "container": {
                                    "image": "alpine",
                                    "command": ["sh", "-c"],
                                    "environment": [
                                        {"name": "node_env", "value": "node_val"}
                                    ],
                                },
                            }
                        ],
                    },
                    "eksProperties": {
                        "podProperties": {
                            "containers": [
                                {
                                    "name": "eks-container",
                                    "image": "nginx",
                                    "command": ["nginx"],
                                    "args": ["-g", "daemon off;"],
                                    "env": [{"name": "eks_env", "value": "eks_val"}],
                                }
                            ]
                        }
                    },
                    "tags": jd_tags,
                }
            ]
        }
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
class TestBatchService:
    @mock_aws
    def test_batch_service(self):
        batch = Batch(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert batch.session.__class__.__name__ == "Session"
        assert batch.service == "batch"
        assert len(batch.job_definitions) == 1
        assert isinstance(batch.job_definitions[jd_arn], JobDefinition)

        jd = batch.job_definitions[jd_arn]
        assert jd.name == jd_name
        assert jd.arn == jd_arn
        assert jd.revision == jd_revision
        assert jd.region == AWS_REGION_US_EAST_1
        assert jd.tags == [jd_tags]

        assert len(jd.containers) == 3

        # 1. containerProperties container
        c1 = jd.containers[0]
        assert isinstance(c1, JobDefinitionContainer)
        assert c1.name == "containerProperties"
        assert c1.environment == [{"name": "env_key", "value": "env_val"}]
        assert c1.command == ["echo", "hello"]

        # 2. nodeProperties container
        c2 = jd.containers[1]
        assert isinstance(c2, JobDefinitionContainer)
        assert c2.name == "nodeRangeProperties[0].container"
        assert c2.environment == [{"name": "node_env", "value": "node_val"}]
        assert c2.command == ["sh", "-c"]

        # 3. eksProperties container
        c3 = jd.containers[2]
        assert isinstance(c3, JobDefinitionContainer)
        assert c3.name == "eksProperties.podProperties.containers[0]"
        assert c3.environment == [{"name": "eks_env", "value": "eks_val"}]
        assert c3.command == ["nginx", "-g", "daemon off;"]
