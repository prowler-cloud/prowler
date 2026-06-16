from unittest import mock

from prowler.providers.aws.services.sagemaker.sagemaker_service import ProcessingJob
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CLARIFY_IMAGE_URI = f"{AWS_ACCOUNT_NUMBER}.dkr.ecr.{AWS_REGION_US_EAST_1}.amazonaws.com/sagemaker-clarify-processing:1.0"
NON_CLARIFY_IMAGE_URI = f"{AWS_ACCOUNT_NUMBER}.dkr.ecr.{AWS_REGION_US_EAST_1}.amazonaws.com/sagemaker-xgboost:1.0"
CUSTOM_CLARIFY_IMAGE_URI = f"{AWS_ACCOUNT_NUMBER}.dkr.ecr.{AWS_REGION_US_EAST_1}.amazonaws.com/my-clarify-thing:1.0"
PROCESSING_JOB_ARN = f"arn:aws:sagemaker:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:processing-job/clarify-job"


class Test_sagemaker_clarify_exists:
    def test_no_processing_jobs_no_scanned_regions(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_processing_jobs = []
        sagemaker_client.processing_jobs_scanned_regions = set()

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_clarify_exists.sagemaker_clarify_exists.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_clarify_exists.sagemaker_clarify_exists import (
                sagemaker_clarify_exists,
            )

            check = sagemaker_clarify_exists()
            result = check.execute()
            assert len(result) == 0

    def test_no_processing_jobs_region_scanned(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_processing_jobs = []
        sagemaker_client.processing_jobs_scanned_regions = {AWS_REGION_US_EAST_1}
        sagemaker_client.audited_partition = "aws"
        sagemaker_client.audited_account = AWS_ACCOUNT_NUMBER

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_clarify_exists.sagemaker_clarify_exists.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_clarify_exists.sagemaker_clarify_exists import (
                sagemaker_clarify_exists,
            )

            check = sagemaker_clarify_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"No SageMaker Clarify processing jobs found in region {AWS_REGION_US_EAST_1}."
            )
            assert result[0].resource_id == "sagemaker-clarify"

    def test_non_clarify_processing_job(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_processing_jobs = [
            ProcessingJob(
                name="xgboost-job",
                arn=f"arn:aws:sagemaker:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:processing-job/xgboost-job",
                region=AWS_REGION_US_EAST_1,
                image_uri=NON_CLARIFY_IMAGE_URI,
            )
        ]
        sagemaker_client.processing_jobs_scanned_regions = {AWS_REGION_US_EAST_1}
        sagemaker_client.audited_partition = "aws"
        sagemaker_client.audited_account = AWS_ACCOUNT_NUMBER

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_clarify_exists.sagemaker_clarify_exists.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_clarify_exists.sagemaker_clarify_exists import (
                sagemaker_clarify_exists,
            )

            check = sagemaker_clarify_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"No SageMaker Clarify processing jobs found in region {AWS_REGION_US_EAST_1}."
            )

    def test_custom_image_with_clarify_in_name_does_not_match(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_processing_jobs = [
            ProcessingJob(
                name="my-clarify-thing-job",
                arn=f"arn:aws:sagemaker:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:processing-job/my-clarify-thing-job",
                region=AWS_REGION_US_EAST_1,
                image_uri=CUSTOM_CLARIFY_IMAGE_URI,
            )
        ]
        sagemaker_client.processing_jobs_scanned_regions = {AWS_REGION_US_EAST_1}
        sagemaker_client.audited_partition = "aws"
        sagemaker_client.audited_account = AWS_ACCOUNT_NUMBER

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_clarify_exists.sagemaker_clarify_exists.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_clarify_exists.sagemaker_clarify_exists import (
                sagemaker_clarify_exists,
            )

            check = sagemaker_clarify_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"No SageMaker Clarify processing jobs found in region {AWS_REGION_US_EAST_1}."
            )

    def test_clarify_processing_job_exists(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_processing_jobs = [
            ProcessingJob(
                name="clarify-job",
                arn=PROCESSING_JOB_ARN,
                region=AWS_REGION_US_EAST_1,
                image_uri=CLARIFY_IMAGE_URI,
            )
        ]
        sagemaker_client.processing_jobs_scanned_regions = {AWS_REGION_US_EAST_1}

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_clarify_exists.sagemaker_clarify_exists.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_clarify_exists.sagemaker_clarify_exists import (
                sagemaker_clarify_exists,
            )

            check = sagemaker_clarify_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SageMaker Clarify processing job clarify-job exists in region {AWS_REGION_US_EAST_1}."
            )
            assert result[0].resource_id == "clarify-job"
            assert result[0].resource_arn == PROCESSING_JOB_ARN

    def test_mixed_regions(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_processing_jobs = [
            ProcessingJob(
                name="clarify-job",
                arn=PROCESSING_JOB_ARN,
                region=AWS_REGION_US_EAST_1,
                image_uri=CLARIFY_IMAGE_URI,
            )
        ]
        sagemaker_client.processing_jobs_scanned_regions = {
            AWS_REGION_US_EAST_1,
            AWS_REGION_EU_WEST_1,
        }
        sagemaker_client.audited_partition = "aws"
        sagemaker_client.audited_account = AWS_ACCOUNT_NUMBER

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_clarify_exists.sagemaker_clarify_exists.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_clarify_exists.sagemaker_clarify_exists import (
                sagemaker_clarify_exists,
            )

            check = sagemaker_clarify_exists()
            result = check.execute()

            assert len(result) == 2

            results_by_region = {r.region: r for r in result}

            us_result = results_by_region[AWS_REGION_US_EAST_1]
            assert us_result.status == "PASS"
            assert (
                us_result.status_extended
                == f"SageMaker Clarify processing job clarify-job exists in region {AWS_REGION_US_EAST_1}."
            )

            eu_result = results_by_region[AWS_REGION_EU_WEST_1]
            assert eu_result.status == "FAIL"
            assert (
                eu_result.status_extended
                == f"No SageMaker Clarify processing jobs found in region {AWS_REGION_EU_WEST_1}."
            )
