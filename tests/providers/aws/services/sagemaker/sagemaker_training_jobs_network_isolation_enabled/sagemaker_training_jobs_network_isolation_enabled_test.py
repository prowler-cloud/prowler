from re import search
from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.sagemaker.sagemaker_service import TrainingJob
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

test_training_job = "test-training-job"
training_job_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:training-job/{test_training_job}"
kms_key_id = str(uuid4())


class Test_sagemaker_training_jobs_network_isolation_enabled:
    def test_no_training_jobs(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_training_jobs = []
        with mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_training_jobs_network_isolation_enabled.sagemaker_training_jobs_network_isolation_enabled import (
                sagemaker_training_jobs_network_isolation_enabled,
            )

            check = sagemaker_training_jobs_network_isolation_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_instance_traffic_encryption_enabled(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_training_jobs = []
        sagemaker_client.sagemaker_training_jobs.append(
            TrainingJob(
                name=test_training_job,
                arn=training_job_arn,
                region=AWS_REGION_EU_WEST_1,
                network_isolation=True,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_training_jobs_network_isolation_enabled.sagemaker_training_jobs_network_isolation_enabled import (
                sagemaker_training_jobs_network_isolation_enabled,
            )

            check = sagemaker_training_jobs_network_isolation_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search("has network isolation enabled", result[0].status_extended)
            assert result[0].resource_id == test_training_job
            assert result[0].resource_arn == training_job_arn

    def test_instance_traffic_encryption_disabled(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_training_jobs = []
        sagemaker_client.sagemaker_training_jobs.append(
            TrainingJob(
                name=test_training_job,
                arn=training_job_arn,
                region=AWS_REGION_EU_WEST_1,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_training_jobs_network_isolation_enabled.sagemaker_training_jobs_network_isolation_enabled import (
                sagemaker_training_jobs_network_isolation_enabled,
            )

            check = sagemaker_training_jobs_network_isolation_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search("has network isolation disabled", result[0].status_extended)
            assert result[0].resource_id == test_training_job
            assert result[0].resource_arn == training_job_arn
