from unittest.mock import patch
from uuid import uuid4

import botocore

from prowler.providers.aws.services.sagemaker.sagemaker_service import SageMaker
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

test_notebook_instance = "test-notebook-instance"
notebook_instance_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:notebook-instance/{test_notebook_instance}"
test_model = "test-model"
test_arn_model = (
    f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:model/{test_model}"
)
test_training_job = "test-training-job"
test_arn_training_job = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:training-job/{test_model}"
subnet_id = "subnet-" + str(uuid4())
kms_key_id = str(uuid4())
endpoint_config_name = "endpoint-config-test"
endpoint_config_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:endpoint-config/{endpoint_config_name}"
prod_variant_name = "Variant1"

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListNotebookInstances":
        return {
            "NotebookInstances": [
                {
                    "NotebookInstanceName": test_notebook_instance,
                    "NotebookInstanceArn": notebook_instance_arn,
                },
            ]
        }
    if operation_name == "ListModels":
        return {
            "Models": [
                {
                    "ModelName": test_model,
                    "ModelArn": test_arn_model,
                },
            ]
        }
    if operation_name == "ListTrainingJobs":
        return {
            "TrainingJobSummaries": [
                {
                    "TrainingJobName": test_training_job,
                    "TrainingJobArn": test_arn_training_job,
                },
            ]
        }
    if operation_name == "DescribeNotebookInstance":
        return {
            "SubnetId": subnet_id,
            "KmsKeyId": kms_key_id,
            "DirectInternetAccess": "Enabled",
            "RootAccess": "Enabled",
        }
    if operation_name == "DescribeModel":
        return {
            "VpcConfig": {
                "Subnets": [
                    subnet_id,
                ]
            },
            "EnableNetworkIsolation": True,
        }
    if operation_name == "DescribeTrainingJob":
        return {
            "ResourceConfig": {
                "VolumeKmsKeyId": kms_key_id,
            },
            "VpcConfig": {
                "Subnets": [
                    subnet_id,
                ]
            },
            "EnableNetworkIsolation": True,
            "EnableInterContainerTrafficEncryption": True,
        }
    if operation_name == "ListTags":
        return {
            "Tags": [
                {"Key": "test", "Value": "test"},
            ],
        }
    if operation_name == "ListEndpointConfigs":
        return {
            "EndpointConfigs": [
                {
                    "EndpointConfigName": endpoint_config_name,
                    "EndpointConfigArn": endpoint_config_arn,
                },
            ],
        }
    if operation_name == "DescribeEndpointConfig":
        return {
            "ProductionVariants": [
                {
                    "VariantName": prod_variant_name,
                    "InitialInstanceCount": 5,
                },
                {
                    "VariantName": "Variant2",
                    "InitialInstanceCount": 2,
                },
            ]
        }

    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_SageMaker_Service:
    # Test SageMaker Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert sagemaker.service == "sagemaker"

    # Test SageMaker client
    def test_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        for reg_client in sagemaker.regional_clients.values():
            assert reg_client.__class__.__name__ == "SageMaker"

    # Test SageMaker session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert sagemaker.session.__class__.__name__ == "Session"

    # Test SageMaker list notebook instances
    def test_list_notebook_instances(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert len(sagemaker.sagemaker_notebook_instances) == 1
        assert sagemaker.sagemaker_notebook_instances[0].name == test_notebook_instance
        assert sagemaker.sagemaker_notebook_instances[0].arn == notebook_instance_arn
        assert sagemaker.sagemaker_notebook_instances[0].region == AWS_REGION_EU_WEST_1
        assert sagemaker.sagemaker_notebook_instances[0].tags == [
            {"Key": "test", "Value": "test"},
        ]

    # Test SageMaker list models
    def test_list_models(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert len(sagemaker.sagemaker_models) == 1
        assert sagemaker.sagemaker_models[0].name == test_model
        assert sagemaker.sagemaker_models[0].arn == test_arn_model
        assert sagemaker.sagemaker_models[0].region == AWS_REGION_EU_WEST_1
        assert sagemaker.sagemaker_models[0].tags == [
            {"Key": "test", "Value": "test"},
        ]

    # Test SageMaker list training jobs
    def test_list_training_jobs(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert len(sagemaker.sagemaker_training_jobs) == 1
        assert sagemaker.sagemaker_training_jobs[0].name == test_training_job
        assert sagemaker.sagemaker_training_jobs[0].arn == test_arn_training_job
        assert sagemaker.sagemaker_training_jobs[0].region == AWS_REGION_EU_WEST_1
        assert sagemaker.sagemaker_training_jobs[0].tags == [
            {"Key": "test", "Value": "test"},
        ]

    # Test SageMaker describe notebook instance
    def test_describe_notebook_instance(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert len(sagemaker.sagemaker_notebook_instances) == 1
        assert sagemaker.sagemaker_notebook_instances[0].root_access
        assert sagemaker.sagemaker_notebook_instances[0].subnet_id == subnet_id
        assert sagemaker.sagemaker_notebook_instances[0].direct_internet_access
        assert sagemaker.sagemaker_notebook_instances[0].kms_key_id == kms_key_id

    # Test SageMaker describe model
    def test_describe_model(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert len(sagemaker.sagemaker_models) == 1
        assert sagemaker.sagemaker_models[0].network_isolation
        assert sagemaker.sagemaker_models[0].vpc_config_subnets == [subnet_id]

    # Test SageMaker describe training jobs
    def test_describe_training_jobs(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert len(sagemaker.sagemaker_training_jobs) == 1
        assert sagemaker.sagemaker_training_jobs[0].container_traffic_encryption
        assert sagemaker.sagemaker_training_jobs[0].network_isolation
        assert sagemaker.sagemaker_training_jobs[0].volume_kms_key_id == kms_key_id
        assert sagemaker.sagemaker_training_jobs[0].vpc_config_subnets == [subnet_id]

    # Test SageMaker list endpoint configs
    def test_list_endpoint_configs(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert len(sagemaker.endpoint_configs) == 1
        assert (
            sagemaker.endpoint_configs[endpoint_config_arn].name == endpoint_config_name
        )
        assert (
            sagemaker.endpoint_configs[endpoint_config_arn].arn == endpoint_config_arn
        )
        assert (
            sagemaker.endpoint_configs[endpoint_config_arn].region
            == AWS_REGION_EU_WEST_1
        )
        assert sagemaker.sagemaker_notebook_instances[0].tags == [
            {"Key": "test", "Value": "test"},
        ]

    # Test SageMaker describe training jobs
    def test_describe_endpoint_configs(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sagemaker = SageMaker(aws_provider)
        assert len(sagemaker.endpoint_configs) == 1
        assert sagemaker.endpoint_configs[endpoint_config_arn].production_variants
        for prod_variant in sagemaker.endpoint_configs[
            endpoint_config_arn
        ].production_variants:
            if prod_variant.name == prod_variant_name:
                assert prod_variant.initial_instance_count == 5
            else:
                assert prod_variant.initial_instance_count == 2
