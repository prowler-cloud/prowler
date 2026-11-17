from unittest import mock

import boto3
from moto import mock_aws

from prowler.providers.aws.services.sagemaker.sagemaker_service import (
    DataQualityJobDefinition,
    SageMaker,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

test_data_quality_job = "test-data-quality-job"
test_arn_data_quality_job = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:data-quality-job-definition/{test_data_quality_job}"


class Test_sagemaker_data_quality_job_intercontainer_encryption_enabled:
    def test_no_data_quality_jobs(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.data_quality_job_definitions = []
        sagemaker_client.data_quality_job_definitions_scan_errors = {}

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_data_quality_job_intercontainer_encryption_enabled import (
                sagemaker_data_quality_job_intercontainer_encryption_enabled,
            )

            check = sagemaker_data_quality_job_intercontainer_encryption_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_data_quality_job_encryption_enabled(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.data_quality_job_definitions = [
            DataQualityJobDefinition(
                name=test_data_quality_job,
                arn=test_arn_data_quality_job,
                region=AWS_REGION_EU_WEST_1,
                enable_inter_container_traffic_encryption=True,
                detail_retrieved=True,
            )
        ]
        sagemaker_client.data_quality_job_definitions_scan_errors = {}

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_data_quality_job_intercontainer_encryption_enabled import (
                sagemaker_data_quality_job_intercontainer_encryption_enabled,
            )

            check = sagemaker_data_quality_job_intercontainer_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SageMaker data quality job definition {test_data_quality_job} has inter-container traffic encryption enabled."
            )
            assert result[0].resource_id == test_data_quality_job
            assert result[0].resource_arn == test_arn_data_quality_job
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_data_quality_job_encryption_disabled(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.data_quality_job_definitions = [
            DataQualityJobDefinition(
                name=test_data_quality_job,
                arn=test_arn_data_quality_job,
                region=AWS_REGION_EU_WEST_1,
                enable_inter_container_traffic_encryption=False,
                detail_retrieved=True,
            )
        ]
        sagemaker_client.data_quality_job_definitions_scan_errors = {}

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_data_quality_job_intercontainer_encryption_enabled import (
                sagemaker_data_quality_job_intercontainer_encryption_enabled,
            )

            check = sagemaker_data_quality_job_intercontainer_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SageMaker data quality job definition {test_data_quality_job} has inter-container traffic encryption disabled."
            )
            assert result[0].resource_id == test_data_quality_job
            assert result[0].resource_arn == test_arn_data_quality_job
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_data_quality_job_details_not_retrieved(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.data_quality_job_definitions = [
            DataQualityJobDefinition(
                name=test_data_quality_job,
                arn=test_arn_data_quality_job,
                region=AWS_REGION_EU_WEST_1,
                enable_inter_container_traffic_encryption=False,
                detail_retrieved=False,
            )
        ]
        sagemaker_client.data_quality_job_definitions_scan_errors = {}

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_data_quality_job_intercontainer_encryption_enabled import (
                sagemaker_data_quality_job_intercontainer_encryption_enabled,
            )

            check = sagemaker_data_quality_job_intercontainer_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"SageMaker data quality job definition {test_data_quality_job} details could not be retrieved."
            )
            assert result[0].resource_id == test_data_quality_job
            assert result[0].resource_arn == test_arn_data_quality_job
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_data_quality_job_scan_error(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.data_quality_job_definitions = []
        sagemaker_client.data_quality_job_definitions_scan_errors = {
            AWS_REGION_EU_WEST_1: "AccessDeniedException"
        }
        sagemaker_client.audited_account = AWS_ACCOUNT_NUMBER
        sagemaker_client.audited_partition = "aws"

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_data_quality_job_intercontainer_encryption_enabled import (
                sagemaker_data_quality_job_intercontainer_encryption_enabled,
            )

            check = sagemaker_data_quality_job_intercontainer_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"SageMaker data quality job definitions could not be listed in region {AWS_REGION_EU_WEST_1} due to AccessDeniedException."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:data-quality-job-definition"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_data_quality_job_moto_pass(self):
        sm_client = boto3.client("sagemaker", region_name=AWS_REGION_EU_WEST_1)
        sm_client.create_data_quality_job_definition(
            JobDefinitionName=test_data_quality_job,
            DataQualityAppSpecification={
                "ImageUri": "123456789012.dkr.ecr.eu-west-1.amazonaws.com/test:latest"
            },
            DataQualityJobInput={
                "EndpointInput": {
                    "EndpointName": "test-endpoint",
                    "LocalPath": "/opt/ml/processing/input",
                }
            },
            DataQualityJobOutputConfig={
                "MonitoringOutputs": [
                    {
                        "S3Output": {
                            "S3Uri": "s3://test-bucket/output",
                            "LocalPath": "/opt/ml/processing/output",
                        }
                    }
                ]
            },
            JobResources={
                "ClusterConfig": {
                    "InstanceCount": 1,
                    "InstanceType": "ml.m5.large",
                    "VolumeSizeInGB": 20,
                }
            },
            RoleArn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/service-role/AmazonSageMaker-ExecutionRole",
            NetworkConfig={"EnableInterContainerTrafficEncryption": True},
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_client",
                new=SageMaker(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_data_quality_job_intercontainer_encryption_enabled import (
                sagemaker_data_quality_job_intercontainer_encryption_enabled,
            )

            check = sagemaker_data_quality_job_intercontainer_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SageMaker data quality job definition {test_data_quality_job} has inter-container traffic encryption enabled."
            )
            assert result[0].resource_id == test_data_quality_job
            assert result[0].resource_arn == test_arn_data_quality_job
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_data_quality_job_moto_fail(self):
        sm_client = boto3.client("sagemaker", region_name=AWS_REGION_EU_WEST_1)
        sm_client.create_data_quality_job_definition(
            JobDefinitionName=test_data_quality_job,
            DataQualityAppSpecification={
                "ImageUri": "123456789012.dkr.ecr.eu-west-1.amazonaws.com/test:latest"
            },
            DataQualityJobInput={
                "EndpointInput": {
                    "EndpointName": "test-endpoint",
                    "LocalPath": "/opt/ml/processing/input",
                }
            },
            DataQualityJobOutputConfig={
                "MonitoringOutputs": [
                    {
                        "S3Output": {
                            "S3Uri": "s3://test-bucket/output",
                            "LocalPath": "/opt/ml/processing/output",
                        }
                    }
                ]
            },
            JobResources={
                "ClusterConfig": {
                    "InstanceCount": 1,
                    "InstanceType": "ml.m5.large",
                    "VolumeSizeInGB": 20,
                }
            },
            RoleArn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/service-role/AmazonSageMaker-ExecutionRole",
            NetworkConfig={"EnableInterContainerTrafficEncryption": False},
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_client",
                new=SageMaker(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_data_quality_job_intercontainer_encryption_enabled.sagemaker_data_quality_job_intercontainer_encryption_enabled import (
                sagemaker_data_quality_job_intercontainer_encryption_enabled,
            )

            check = sagemaker_data_quality_job_intercontainer_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SageMaker data quality job definition {test_data_quality_job} has inter-container traffic encryption disabled."
            )
            assert result[0].resource_id == test_data_quality_job
            assert result[0].resource_arn == test_arn_data_quality_job
            assert result[0].region == AWS_REGION_EU_WEST_1
