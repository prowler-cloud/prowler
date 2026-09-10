from unittest.mock import patch

import botocore
from botocore.exceptions import ClientError

from prowler.providers.aws.services.batch.batch_service import Batch
from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

COMPUTE_ENVIRONMENT_NAME = "test-compute-environment"
COMPUTE_ENVIRONMENT_ARN = f"arn:aws:batch:eu-west-1:123456789012:compute-environment/{COMPUTE_ENVIRONMENT_NAME}"


def default_api_call(self, operation_name, kwarg):
    """Fall back to the real call, stubbing the APIs a test does not exercise."""
    if operation_name == "DescribeComputeEnvironments":
        return {"computeEnvironments": []}
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeJobDefinitions":
        return {
            "jobDefinitions": [
                {
                    "jobDefinitionName": "test-batch-job",
                    "jobDefinitionArn": "arn:aws:batch:eu-west-1:123456789012:job-definition/test-batch-job:1",
                    "revision": 1,
                    "containerProperties": {
                        "image": "test-image:latest",
                        "command": ["python", "app.py"],
                        "environment": [
                            {"name": "DB_PASSWORD", "value": "pass-12343"},
                            {"name": "APP_NAME", "value": "myapp"},
                        ],
                    },
                }
            ]
        }
    return default_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


def mock_generate_multi_region_clients(provider, service):
    eu_west_1_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    eu_west_1_client.region = AWS_REGION_EU_WEST_1

    us_east_1_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_US_EAST_1
    )
    us_east_1_client.region = AWS_REGION_US_EAST_1

    return {
        AWS_REGION_EU_WEST_1: eu_west_1_client,
        AWS_REGION_US_EAST_1: us_east_1_client,
    }


@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_Batch_Service:
    def test_service(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        batch = Batch(aws_provider)
        assert batch.service == "batch"

    def test_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        batch = Batch(aws_provider)
        for reg_client in batch.regional_clients.values():
            assert reg_client.__class__.__name__ == "Batch"

    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        batch = Batch(aws_provider)
        assert batch.session.__class__.__name__ == "Session"

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_list_job_definitions(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        batch = Batch(aws_provider)

        assert len(batch.job_definitions) == 1
        jd_arn = "arn:aws:batch:eu-west-1:123456789012:job-definition/test-batch-job:1"
        jd = batch.job_definitions[jd_arn]
        assert jd.name == "test-batch-job"
        assert jd.arn == jd_arn
        assert jd.revision == 1
        assert jd.region == AWS_REGION_EU_WEST_1

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_describe_job_definitions(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        batch = Batch(aws_provider)

        assert len(batch.job_definitions) == 1
        jd = list(batch.job_definitions.values())[0]
        assert jd.name == "test-batch-job"
        assert jd.container_properties.image == "test-image:latest"
        assert jd.container_properties.command == ["python", "app.py"]
        assert len(jd.container_properties.environment) == 2
        assert jd.container_properties.environment[0].name == "DB_PASSWORD"
        assert jd.container_properties.environment[0].value == "pass-12343"
        assert jd.container_properties.environment[1].name == "APP_NAME"
        assert jd.container_properties.environment[1].value == "myapp"

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_no_job_definitions(self):
        def mock_make_api_call_empty(self, operation_name, kwarg):
            if operation_name == "DescribeJobDefinitions":
                return {"jobDefinitions": []}
            return default_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_empty,
        ):
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            batch = Batch(aws_provider)
            assert len(batch.job_definitions) == 0

    def test_job_definitions_are_loaded_for_analysis(self):
        describe_calls = []

        def counting_make_api_call(self, operation_name, kwarg):
            if operation_name == "DescribeJobDefinitions":
                describe_calls.append(kwarg)
                return {
                    "jobDefinitions": [
                        {
                            "jobDefinitionName": f"job-{i}",
                            "jobDefinitionArn": f"arn:aws:batch:eu-west-1:123456789012:job-definition/job-{i}:{i}",
                            "revision": i,
                            "containerProperties": {
                                "image": "test-image:latest",
                                "environment": [],
                            },
                        }
                        for i in (3, 2, 1)
                    ]
                }
            return default_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call", new=counting_make_api_call
        ):
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            batch = Batch(aws_provider)

            assert [jd.revision for jd in batch.job_definitions.values()] == [3, 2, 1]
            assert len(describe_calls) == 1
            assert describe_calls[0].get("status") == "ACTIVE"

    def test_job_definition_limit_exposes_only_selected_resources(self):
        describe_calls = []

        def counting_make_api_call(self, operation_name, kwarg):
            if operation_name == "DescribeJobDefinitions":
                describe_calls.append(kwarg)
                return {
                    "jobDefinitions": [
                        {
                            "jobDefinitionName": f"job-{i}",
                            "jobDefinitionArn": f"arn:aws:batch:eu-west-1:123456789012:job-definition/job-{i}:{i}",
                            "revision": i,
                            "containerProperties": {
                                "image": "test-image:latest",
                                "environment": [],
                            },
                        }
                        for i in (3, 2, 1)
                    ]
                }
            return default_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call", new=counting_make_api_call
        ):
            aws_provider = set_mocked_aws_provider(
                [AWS_REGION_EU_WEST_1],
                audit_config={"max_batch_job_definitions": 2},
            )
            batch = Batch(aws_provider)

            assert [jd.revision for jd in batch.job_definitions.values()] == [3, 2]
            assert len(describe_calls) == 1

    def test_describe_compute_environments(self):
        def compute_environments_api_call(self, operation_name, kwarg):
            if operation_name == "DescribeComputeEnvironments":
                return {
                    "computeEnvironments": [
                        {
                            "computeEnvironmentName": COMPUTE_ENVIRONMENT_NAME,
                            "computeEnvironmentArn": COMPUTE_ENVIRONMENT_ARN,
                            "computeResources": {
                                "securityGroupIds": ["sg-1", "sg-2"],
                                "subnets": ["subnet-1"],
                            },
                        }
                    ]
                }
            return mock_make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=compute_environments_api_call,
        ):
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            batch = Batch(aws_provider)

            assert len(batch.compute_environments) == 1
            compute_environment = batch.compute_environments[COMPUTE_ENVIRONMENT_ARN]
            assert compute_environment.name == COMPUTE_ENVIRONMENT_NAME
            assert compute_environment.arn == COMPUTE_ENVIRONMENT_ARN
            assert compute_environment.region == AWS_REGION_EU_WEST_1
            assert compute_environment.security_groups == ["sg-1", "sg-2"]
            assert compute_environment.subnets == ["subnet-1"]
            assert batch.security_groups_in_use == {"sg-1", "sg-2"}

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_no_compute_environments(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        batch = Batch(aws_provider)

        assert len(batch.compute_environments) == 0
        assert batch.security_groups_in_use == set()
        assert batch.compute_environment_lookup_failed_regions == set()

    def test_compute_environments_access_denied(self):
        def access_denied_api_call(self, operation_name, kwarg):
            if operation_name == "DescribeComputeEnvironments":
                raise ClientError(
                    {
                        "Error": {
                            "Code": "AccessDeniedException",
                            "Message": "User is not authorized to perform: batch:DescribeComputeEnvironments",
                        }
                    },
                    operation_name,
                )
            return mock_make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call", new=access_denied_api_call
        ):
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            batch = Batch(aws_provider)

            # The associations are unknown, not absent
            assert batch.compute_environments == {}
            assert batch.security_groups_in_use == set()
            assert batch.compute_environment_lookup_failed_regions == {
                AWS_REGION_EU_WEST_1
            }
            # Unrelated discovery is unaffected
            assert len(batch.job_definitions) == 1

    def test_compute_environment_without_compute_resources(self):
        def unmanaged_api_call(self, operation_name, kwarg):
            # UNMANAGED compute environments carry no `computeResources` block
            if operation_name == "DescribeComputeEnvironments":
                return {
                    "computeEnvironments": [
                        {
                            "computeEnvironmentName": COMPUTE_ENVIRONMENT_NAME,
                            "computeEnvironmentArn": COMPUTE_ENVIRONMENT_ARN,
                        }
                    ]
                }
            return mock_make_api_call(self, operation_name, kwarg)

        with patch("botocore.client.BaseClient._make_api_call", new=unmanaged_api_call):
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            batch = Batch(aws_provider)

            assert len(batch.compute_environments) == 1
            compute_environment = batch.compute_environments[COMPUTE_ENVIRONMENT_ARN]
            assert compute_environment.security_groups == []
            assert compute_environment.subnets == []
            assert batch.security_groups_in_use == set()

    def test_audit_resources_filters_compute_environments(self):
        def compute_environments_api_call(self, operation_name, kwarg):
            if operation_name == "DescribeComputeEnvironments":
                return {
                    "computeEnvironments": [
                        {
                            "computeEnvironmentName": f"compute-environment-{i}",
                            "computeEnvironmentArn": f"arn:aws:batch:eu-west-1:123456789012:compute-environment/compute-environment-{i}",
                            "computeResources": {
                                "securityGroupIds": [f"sg-{i}"],
                                "subnets": ["subnet-1"],
                            },
                        }
                        for i in (1, 2)
                    ]
                }
            return mock_make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=compute_environments_api_call,
        ):
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            aws_provider._audit_resources = [
                "arn:aws:batch:eu-west-1:123456789012:compute-environment/compute-environment-1"
            ]
            batch = Batch(aws_provider)

            assert list(batch.compute_environments) == [
                "arn:aws:batch:eu-west-1:123456789012:compute-environment/compute-environment-1"
            ]
            assert batch.security_groups_in_use == {"sg-1"}

    def test_audit_resources_filters_job_definitions(self):
        def counting_make_api_call(self, operation_name, kwarg):
            if operation_name == "DescribeJobDefinitions":
                return {
                    "jobDefinitions": [
                        {
                            "jobDefinitionName": f"job-{i}",
                            "jobDefinitionArn": f"arn:aws:batch:eu-west-1:123456789012:job-definition/job-{i}:{i}",
                            "revision": i,
                            "containerProperties": {
                                "image": "test-image:latest",
                                "environment": [],
                            },
                        }
                        for i in (1, 2)
                    ]
                }
            return default_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call", new=counting_make_api_call
        ):
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            aws_provider._audit_resources = [
                "arn:aws:batch:eu-west-1:123456789012:job-definition/job-2:2"
            ]
            batch = Batch(aws_provider)

            assert list(batch.job_definitions.keys()) == [
                "arn:aws:batch:eu-west-1:123456789012:job-definition/job-2:2"
            ]
