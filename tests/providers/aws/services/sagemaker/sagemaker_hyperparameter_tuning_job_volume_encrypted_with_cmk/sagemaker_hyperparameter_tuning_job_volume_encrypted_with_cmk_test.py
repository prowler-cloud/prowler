from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk:
    @mock_aws
    def test_no_tuning_jobs(self):
        from prowler.providers.aws.services.sagemaker.sagemaker_service import SageMaker

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_client",
                new=SageMaker(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk import (
                sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk,
            )

            check = sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_tuning_job_volume_encrypted(self):
        kms_client = client("kms", region_name=AWS_REGION_EU_WEST_1)
        kms_key_id = kms_client.create_key()["KeyMetadata"]["KeyId"]

        sagemaker_client = client("sagemaker", region_name=AWS_REGION_EU_WEST_1)
        job_name = "test-tuning-job-encrypted"
        job = sagemaker_client.create_hyper_parameter_tuning_job(
            HyperParameterTuningJobName=job_name,
            HyperParameterTuningJobConfig={
                "Strategy": "Bayesian",
                "HyperParameterTuningJobObjective": {
                    "Type": "Maximize",
                    "MetricName": "test",
                },
                "ResourceLimits": {
                    "MaxNumberOfTrainingJobs": 1,
                    "MaxParallelTrainingJobs": 1,
                },
                "ParameterRanges": {},
            },
            TrainingJobDefinition={
                "AlgorithmSpecification": {"TrainingInputMode": "File"},
                "RoleArn": "arn:aws:iam::123456789012:role/service-role",
                "OutputDataConfig": {"S3OutputPath": "s3://bucket"},
                "ResourceConfig": {
                    "InstanceType": "ml.m5.large",
                    "InstanceCount": 1,
                    "VolumeSizeInGB": 1,
                    "VolumeKmsKeyId": kms_key_id,
                },
                "StoppingCondition": {"MaxRuntimeInSeconds": 100},
            },
        )

        from prowler.providers.aws.services.sagemaker.sagemaker_service import SageMaker

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_client",
                new=SageMaker(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk import (
                sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk,
            )

            check = sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SageMaker hyperparameter tuning job {job_name} has storage volume encrypted with KMS CMK."
            )
            assert result[0].resource_id == job_name
            assert result[0].resource_arn == job["HyperParameterTuningJobArn"]
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_tuning_job_volume_unencrypted(self):
        sagemaker_client = client("sagemaker", region_name=AWS_REGION_EU_WEST_1)
        job_name = "test-tuning-job-unencrypted"
        job = sagemaker_client.create_hyper_parameter_tuning_job(
            HyperParameterTuningJobName=job_name,
            HyperParameterTuningJobConfig={
                "Strategy": "Bayesian",
                "HyperParameterTuningJobObjective": {
                    "Type": "Maximize",
                    "MetricName": "test",
                },
                "ResourceLimits": {
                    "MaxNumberOfTrainingJobs": 1,
                    "MaxParallelTrainingJobs": 1,
                },
                "ParameterRanges": {},
            },
            TrainingJobDefinition={
                "AlgorithmSpecification": {"TrainingInputMode": "File"},
                "RoleArn": "arn:aws:iam::123456789012:role/service-role",
                "OutputDataConfig": {"S3OutputPath": "s3://bucket"},
                "ResourceConfig": {
                    "InstanceType": "ml.m5.large",
                    "InstanceCount": 1,
                    "VolumeSizeInGB": 1,
                },
                "StoppingCondition": {"MaxRuntimeInSeconds": 100},
            },
        )

        from prowler.providers.aws.services.sagemaker.sagemaker_service import SageMaker

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_client",
                new=SageMaker(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk import (
                sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk,
            )

            check = sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SageMaker hyperparameter tuning job {job_name} does not have storage volume encrypted with KMS CMK."
            )
            assert result[0].resource_id == job_name
            assert result[0].resource_arn == job["HyperParameterTuningJobArn"]
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_tuning_job_multi_definitions_partially_unencrypted(self):
        kms_client = client("kms", region_name=AWS_REGION_EU_WEST_1)
        kms_key_id = kms_client.create_key()["KeyMetadata"]["KeyId"]

        sagemaker_client = client("sagemaker", region_name=AWS_REGION_EU_WEST_1)
        job_name = "test-tuning-job-multi"
        job = sagemaker_client.create_hyper_parameter_tuning_job(
            HyperParameterTuningJobName=job_name,
            HyperParameterTuningJobConfig={
                "Strategy": "Bayesian",
                "HyperParameterTuningJobObjective": {
                    "Type": "Maximize",
                    "MetricName": "test",
                },
                "ResourceLimits": {
                    "MaxNumberOfTrainingJobs": 1,
                    "MaxParallelTrainingJobs": 1,
                },
                "ParameterRanges": {},
            },
            TrainingJobDefinitions=[
                {
                    "DefinitionName": "def-encrypted",
                    "AlgorithmSpecification": {"TrainingInputMode": "File"},
                    "RoleArn": "arn:aws:iam::123456789012:role/service-role",
                    "OutputDataConfig": {"S3OutputPath": "s3://bucket"},
                    "ResourceConfig": {
                        "InstanceType": "ml.m5.large",
                        "InstanceCount": 1,
                        "VolumeSizeInGB": 1,
                        "VolumeKmsKeyId": kms_key_id,
                    },
                    "StoppingCondition": {"MaxRuntimeInSeconds": 100},
                },
                {
                    "DefinitionName": "def-unencrypted",
                    "AlgorithmSpecification": {"TrainingInputMode": "File"},
                    "RoleArn": "arn:aws:iam::123456789012:role/service-role",
                    "OutputDataConfig": {"S3OutputPath": "s3://bucket"},
                    "ResourceConfig": {
                        "InstanceType": "ml.m5.large",
                        "InstanceCount": 1,
                        "VolumeSizeInGB": 1,
                    },
                    "StoppingCondition": {"MaxRuntimeInSeconds": 100},
                },
            ],
        )

        from prowler.providers.aws.services.sagemaker.sagemaker_service import SageMaker

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_client",
                new=SageMaker(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk import (
                sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk,
            )

            check = sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SageMaker hyperparameter tuning job {job_name} does not have storage volume encrypted with KMS CMK."
            )
            assert result[0].resource_id == job_name
            assert result[0].resource_arn == job["HyperParameterTuningJobArn"]
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_tuning_job_details_not_retrieved(self):
        from prowler.providers.aws.services.sagemaker.sagemaker_service import (
            HyperParameterTuningJob,
        )

        job_name = "test-tuning-job-unretrieved"
        job_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:123456789012:hyper-parameter-tuning-job/{job_name}"
        sagemaker_client = mock.MagicMock()
        sagemaker_client.sagemaker_hyperparameter_tuning_jobs = [
            HyperParameterTuningJob(
                name=job_name,
                region=AWS_REGION_EU_WEST_1,
                arn=job_arn,
                detail_retrieved=False,
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_client",
                new=sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk import (
                sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk,
            )

            check = sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"SageMaker hyperparameter tuning job {job_name} configuration could not be retrieved in region {AWS_REGION_EU_WEST_1}; verify manually."
            )
            assert result[0].resource_id == job_name
            assert result[0].resource_arn == job_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_tuning_job_no_definitions(self):
        from prowler.providers.aws.services.sagemaker.sagemaker_service import (
            HyperParameterTuningJob,
        )

        job_name = "test-tuning-job-no-definitions"
        job_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:123456789012:hyper-parameter-tuning-job/{job_name}"
        sagemaker_client = mock.MagicMock()
        sagemaker_client.sagemaker_hyperparameter_tuning_jobs = [
            HyperParameterTuningJob(
                name=job_name,
                region=AWS_REGION_EU_WEST_1,
                arn=job_arn,
                all_definitions_encrypted=None,
                detail_retrieved=True,
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_client",
                new=sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk import (
                sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk,
            )

            check = sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"SageMaker hyperparameter tuning job {job_name} has no training job definitions configured; verify manually."
            )
            assert result[0].resource_id == job_name
            assert result[0].resource_arn == job_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_tuning_job_scan_error(self):
        sagemaker_client = mock.MagicMock()
        sagemaker_client.sagemaker_hyperparameter_tuning_jobs = []
        sagemaker_client.sagemaker_hyperparameter_tuning_jobs_scan_errors = {
            AWS_REGION_EU_WEST_1: "AccessDeniedException"
        }
        sagemaker_client.audited_partition = "aws"
        sagemaker_client.audited_account = AWS_ACCOUNT_NUMBER

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_client",
                new=sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk.sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk import (
                sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk,
            )

            check = sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"SageMaker hyperparameter tuning jobs could not be listed in region {AWS_REGION_EU_WEST_1} (AccessDeniedException); verify manually that every hyperparameter tuning job uses a customer-managed KMS key."
            )
            assert result[0].resource_id == "hyper-parameter-tuning-job/unknown"
            assert (
                result[0].resource_arn
                == f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:hyper-parameter-tuning-job/unknown"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
