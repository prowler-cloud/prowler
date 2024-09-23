from unittest import mock

from prowler.providers.aws.services.sagemaker.sagemaker_service import TrainingJob
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

test_training_job = "test-training-job"
training_job_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:training-job/{test_training_job}"


class Test_sagemaker_training_jobs_intercontainer_encryption_enabled:
    def test_no_training_jobs(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_training_jobs = []

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_training_jobs_intercontainer_encryption_enabled.sagemaker_training_jobs_intercontainer_encryption_enabled.sagemaker_client",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_training_jobs_intercontainer_encryption_enabled.sagemaker_training_jobs_intercontainer_encryption_enabled import (
                sagemaker_training_jobs_intercontainer_encryption_enabled,
            )

            check = sagemaker_training_jobs_intercontainer_encryption_enabled()
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
                container_traffic_encryption=True,
            )
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_training_jobs_intercontainer_encryption_enabled.sagemaker_training_jobs_intercontainer_encryption_enabled.sagemaker_client",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_training_jobs_intercontainer_encryption_enabled.sagemaker_training_jobs_intercontainer_encryption_enabled import (
                sagemaker_training_jobs_intercontainer_encryption_enabled,
            )

            check = sagemaker_training_jobs_intercontainer_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Sagemaker training job {test_training_job} has intercontainer encryption enabled."
            )
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

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_training_jobs_intercontainer_encryption_enabled.sagemaker_training_jobs_intercontainer_encryption_enabled.sagemaker_client",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_training_jobs_intercontainer_encryption_enabled.sagemaker_training_jobs_intercontainer_encryption_enabled import (
                sagemaker_training_jobs_intercontainer_encryption_enabled,
            )

            check = sagemaker_training_jobs_intercontainer_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Sagemaker training job {test_training_job} has intercontainer encryption disabled."
            )
            assert result[0].resource_id == test_training_job
            assert result[0].resource_arn == training_job_arn
