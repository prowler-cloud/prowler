from unittest import mock
from unittest.mock import patch

import botocore
from botocore.client import BaseClient

from prowler.providers.aws.services.sagemaker.sagemaker_service import (
    ProcessingJob,
    SageMaker,
)
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

make_api_call = BaseClient._make_api_call


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


def _empty_list_responses(operation_name):
    empty = {
        "ListNotebookInstances": {"NotebookInstances": []},
        "ListModels": {"Models": []},
        "ListTrainingJobs": {"TrainingJobSummaries": []},
        "ListTransformJobs": {"TransformJobSummaries": []},
        "ListEndpointConfigs": {"EndpointConfigs": []},
        "ListDomains": {"Domains": []},
        "ListModelPackageGroups": {"ModelPackageGroupSummaryList": []},
        "ListMonitoringSchedules": {"MonitoringScheduleSummaries": []},
    }
    return empty.get(operation_name)


class Test_sagemaker_processing_job_volume_encrypted_with_cmk:
    def test_no_processing_jobs(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_processing_jobs = []
        sagemaker_client.processing_jobs_list_failed_regions = set()

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

    def test_list_processing_jobs_failed_region(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_processing_jobs = []
        sagemaker_client.processing_jobs_list_failed_regions = {AWS_REGION_EU_WEST_1}
        sagemaker_client.audited_partition = "aws"
        sagemaker_client.audited_account = AWS_ACCOUNT_NUMBER

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
                == f"SageMaker processing job inventory could not be listed in "
                f"region {AWS_REGION_EU_WEST_1}; volume encryption cannot be verified."
            )
            assert result[0].resource_id == "sagemaker-processing-jobs"
            assert result[0].region == AWS_REGION_EU_WEST_1

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
        sagemaker_client.processing_jobs_list_failed_regions = set()

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
        sagemaker_client.processing_jobs_list_failed_regions = set()

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
        sagemaker_client.processing_jobs_list_failed_regions = set()

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

    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    def test_collector_omitted_volume_kms_key_propagates_fail(self):
        """FAIL path through DescribeProcessingJob without VolumeKmsKeyId."""

        def mock_api(self, operation_name, kwarg):
            if operation_name == "ListProcessingJobs":
                return {
                    "ProcessingJobSummaries": [
                        {
                            "ProcessingJobName": test_processing_job,
                            "ProcessingJobArn": processing_job_arn,
                        }
                    ]
                }
            if operation_name == "DescribeProcessingJob":
                return {
                    "AppSpecification": {
                        "ImageUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/image:1"
                    },
                    "ProcessingResources": {
                        "ClusterConfig": {
                            "InstanceCount": 1,
                            "InstanceType": "ml.m5.xlarge",
                            "VolumeSizeInGB": 30,
                        }
                    },
                }
            if operation_name == "ListTags":
                return {"Tags": []}
            empty = _empty_list_responses(operation_name)
            if empty is not None:
                return empty
            return make_api_call(self, operation_name, kwarg)

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        with patch("botocore.client.BaseClient._make_api_call", new=mock_api):
            sagemaker = SageMaker(aws_provider)

        assert len(sagemaker.sagemaker_processing_jobs) == 1
        assert sagemaker.sagemaker_processing_jobs[0].volume_kms_key_id is None
        assert sagemaker.sagemaker_processing_jobs[0].detail_fetch_error is None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_PATH}.sagemaker_client", sagemaker),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_processing_job_volume_encrypted_with_cmk.sagemaker_processing_job_volume_encrypted_with_cmk import (
                sagemaker_processing_job_volume_encrypted_with_cmk,
            )

            result = sagemaker_processing_job_volume_encrypted_with_cmk().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    def test_collector_describe_exception_propagates_manual(self):
        """MANUAL path through DescribeProcessingJob raising an exception."""

        def mock_api(self, operation_name, kwarg):
            if operation_name == "ListProcessingJobs":
                return {
                    "ProcessingJobSummaries": [
                        {
                            "ProcessingJobName": test_processing_job,
                            "ProcessingJobArn": processing_job_arn,
                        }
                    ]
                }
            if operation_name == "DescribeProcessingJob":
                raise botocore.exceptions.ClientError(
                    {
                        "Error": {
                            "Code": "AccessDeniedException",
                            "Message": "denied",
                        }
                    },
                    "DescribeProcessingJob",
                )
            if operation_name == "ListTags":
                return {"Tags": []}
            empty = _empty_list_responses(operation_name)
            if empty is not None:
                return empty
            return make_api_call(self, operation_name, kwarg)

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        with patch("botocore.client.BaseClient._make_api_call", new=mock_api):
            sagemaker = SageMaker(aws_provider)

        job = sagemaker.sagemaker_processing_jobs[0]
        assert job.volume_kms_key_id is None
        assert job.detail_fetch_error == "ClientError"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_PATH}.sagemaker_client", sagemaker),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_processing_job_volume_encrypted_with_cmk.sagemaker_processing_job_volume_encrypted_with_cmk import (
                sagemaker_processing_job_volume_encrypted_with_cmk,
            )

            result = sagemaker_processing_job_volume_encrypted_with_cmk().execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "ClientError" in result[0].status_extended
