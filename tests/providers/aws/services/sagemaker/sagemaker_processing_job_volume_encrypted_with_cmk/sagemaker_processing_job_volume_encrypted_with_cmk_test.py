from unittest import mock

from prowler.providers.aws.services.sagemaker.sagemaker_service import ProcessingJob
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

test_processing_job = "test-processing-job"
processing_job_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:processing-job/{test_processing_job}"
test_kms_key_id = (
    f"arn:aws:kms:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:key/test-key-id"
)
CHECK_PATH = (
    "prowler.providers.aws.services.sagemaker."
    "sagemaker_processing_job_volume_encrypted_with_cmk."
    "sagemaker_processing_job_volume_encrypted_with_cmk"
)


class Test_sagemaker_processing_job_volume_encrypted_with_cmk:
    def test_no_processing_jobs(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_processing_jobs = []

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_PATH}.sagemaker_client", sagemaker_client),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_processing_job_volume_encrypted_with_cmk.sagemaker_processing_job_volume_encrypted_with_cmk import (
                sagemaker_processing_job_volume_encrypted_with_cmk,
            )

            result = sagemaker_processing_job_volume_encrypted_with_cmk().execute()
            assert len(result) == 0

    def test_processing_job_encrypted_with_cmk(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_processing_jobs = [
            ProcessingJob(
                name=test_processing_job,
                arn=processing_job_arn,
                region=AWS_REGION_EU_WEST_1,
                volume_kms_key_id=test_kms_key_id,
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_PATH}.sagemaker_client", sagemaker_client),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_processing_job_volume_encrypted_with_cmk.sagemaker_processing_job_volume_encrypted_with_cmk import (
                sagemaker_processing_job_volume_encrypted_with_cmk,
            )

            result = sagemaker_processing_job_volume_encrypted_with_cmk().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SageMaker processing job {test_processing_job} encrypts its "
                f"volume with the customer-managed KMS key {test_kms_key_id}."
            )
            assert result[0].resource_id == test_processing_job
            assert result[0].resource_arn == processing_job_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_processing_job_not_encrypted_with_cmk(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_processing_jobs = [
            ProcessingJob(
                name=test_processing_job,
                arn=processing_job_arn,
                region=AWS_REGION_EU_WEST_1,
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_PATH}.sagemaker_client", sagemaker_client),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_processing_job_volume_encrypted_with_cmk.sagemaker_processing_job_volume_encrypted_with_cmk import (
                sagemaker_processing_job_volume_encrypted_with_cmk,
            )

            result = sagemaker_processing_job_volume_encrypted_with_cmk().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SageMaker processing job {test_processing_job} does not "
                "encrypt its volume with a customer-managed KMS key."
            )
            assert result[0].resource_id == test_processing_job
            assert result[0].resource_arn == processing_job_arn

    def test_processing_job_detail_fetch_error(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_processing_jobs = [
            ProcessingJob(
                name=test_processing_job,
                arn=processing_job_arn,
                region=AWS_REGION_EU_WEST_1,
                detail_fetch_error="AccessDeniedException",
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_PATH}.sagemaker_client", sagemaker_client),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_processing_job_volume_encrypted_with_cmk.sagemaker_processing_job_volume_encrypted_with_cmk import (
                sagemaker_processing_job_volume_encrypted_with_cmk,
            )

            result = sagemaker_processing_job_volume_encrypted_with_cmk().execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"SageMaker processing job {test_processing_job} details could "
                "not be described (AccessDeniedException); volume encryption "
                "cannot be verified."
            )
            assert result[0].resource_id == test_processing_job
            assert result[0].resource_arn == processing_job_arn
