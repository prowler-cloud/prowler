from unittest import mock
from unittest.mock import patch

import botocore
from botocore.client import BaseClient

from prowler.providers.aws.services.sagemaker.sagemaker_service import (
    SageMaker,
    TransformJob,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

test_transform_job = "test-transform-job"
transform_job_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:transform-job/{test_transform_job}"
test_kms_key_id = (
    f"arn:aws:kms:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:key/test-key-id"
)
CHECK_PATH = (
    "prowler.providers.aws.services.sagemaker."
    "sagemaker_transform_job_volume_encrypted_with_cmk."
    "sagemaker_transform_job_volume_encrypted_with_cmk"
)

make_api_call = BaseClient._make_api_call


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


class Test_sagemaker_transform_job_volume_encrypted_with_cmk:
    def test_no_transform_jobs(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_transform_jobs = []
        sagemaker_client.transform_jobs_list_failed_regions = set()

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_PATH}.sagemaker_client", sagemaker_client),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_transform_job_volume_encrypted_with_cmk.sagemaker_transform_job_volume_encrypted_with_cmk import (
                sagemaker_transform_job_volume_encrypted_with_cmk,
            )

            result = sagemaker_transform_job_volume_encrypted_with_cmk().execute()
            assert len(result) == 0

    def test_list_transform_jobs_failed_region(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_transform_jobs = []
        sagemaker_client.transform_jobs_list_failed_regions = {AWS_REGION_EU_WEST_1}
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
            from prowler.providers.aws.services.sagemaker.sagemaker_transform_job_volume_encrypted_with_cmk.sagemaker_transform_job_volume_encrypted_with_cmk import (
                sagemaker_transform_job_volume_encrypted_with_cmk,
            )

            result = sagemaker_transform_job_volume_encrypted_with_cmk().execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"SageMaker transform job inventory could not be listed in "
                f"region {AWS_REGION_EU_WEST_1}; volume encryption cannot be verified."
            )
            assert result[0].resource_id == "sagemaker-transform-jobs"
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_transform_job_encrypted_with_cmk(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_transform_jobs = [
            TransformJob(
                name=test_transform_job,
                arn=transform_job_arn,
                region=AWS_REGION_EU_WEST_1,
                volume_kms_key_id=test_kms_key_id,
            )
        ]
        sagemaker_client.transform_jobs_list_failed_regions = set()

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_PATH}.sagemaker_client", sagemaker_client),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_transform_job_volume_encrypted_with_cmk.sagemaker_transform_job_volume_encrypted_with_cmk import (
                sagemaker_transform_job_volume_encrypted_with_cmk,
            )

            result = sagemaker_transform_job_volume_encrypted_with_cmk().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SageMaker transform job {test_transform_job} encrypts its "
                f"volume with the customer-managed KMS key {test_kms_key_id}."
            )
            assert result[0].resource_id == test_transform_job
            assert result[0].resource_arn == transform_job_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_transform_job_not_encrypted_with_cmk(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_transform_jobs = [
            TransformJob(
                name=test_transform_job,
                arn=transform_job_arn,
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        sagemaker_client.transform_jobs_list_failed_regions = set()

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_PATH}.sagemaker_client", sagemaker_client),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_transform_job_volume_encrypted_with_cmk.sagemaker_transform_job_volume_encrypted_with_cmk import (
                sagemaker_transform_job_volume_encrypted_with_cmk,
            )

            result = sagemaker_transform_job_volume_encrypted_with_cmk().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SageMaker transform job {test_transform_job} does not "
                "encrypt its volume with a customer-managed KMS key."
            )
            assert result[0].resource_id == test_transform_job
            assert result[0].resource_arn == transform_job_arn

    def test_transform_job_detail_fetch_error(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_transform_jobs = [
            TransformJob(
                name=test_transform_job,
                arn=transform_job_arn,
                region=AWS_REGION_EU_WEST_1,
                detail_fetch_error="AccessDeniedException",
            )
        ]
        sagemaker_client.transform_jobs_list_failed_regions = set()

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_PATH}.sagemaker_client", sagemaker_client),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_transform_job_volume_encrypted_with_cmk.sagemaker_transform_job_volume_encrypted_with_cmk import (
                sagemaker_transform_job_volume_encrypted_with_cmk,
            )

            result = sagemaker_transform_job_volume_encrypted_with_cmk().execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"SageMaker transform job {test_transform_job} details could "
                "not be described (AccessDeniedException); volume encryption "
                "cannot be verified."
            )
            assert result[0].resource_id == test_transform_job
            assert result[0].resource_arn == transform_job_arn

    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    def test_collector_omitted_volume_kms_key_propagates_fail(self):
        """FAIL path through DescribeTransformJob without VolumeKmsKeyId."""

        def mock_api(self, operation_name, kwarg):
            if operation_name == "ListTransformJobs":
                return {
                    "TransformJobSummaries": [
                        {
                            "TransformJobName": test_transform_job,
                            "TransformJobArn": transform_job_arn,
                        }
                    ]
                }
            if operation_name == "DescribeTransformJob":
                return {
                    "TransformResources": {
                        "InstanceType": "ml.m5.xlarge",
                        "InstanceCount": 1,
                    }
                }
            if operation_name == "ListTags":
                return {"Tags": []}
            # Keep other SageMaker list/describe calls empty/harmless
            if operation_name.startswith("List") or operation_name.startswith(
                "Describe"
            ):
                empty = {
                    "ListNotebookInstances": {"NotebookInstances": []},
                    "ListModels": {"Models": []},
                    "ListTrainingJobs": {"TrainingJobSummaries": []},
                    "ListProcessingJobs": {"ProcessingJobSummaries": []},
                    "ListEndpointConfigs": {"EndpointConfigs": []},
                    "ListDomains": {"Domains": []},
                    "ListModelPackageGroups": {"ModelPackageGroupSummaryList": []},
                    "ListMonitoringSchedules": {"MonitoringScheduleSummaries": []},
                }
                if operation_name in empty:
                    return empty[operation_name]
            return make_api_call(self, operation_name, kwarg)

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        with patch("botocore.client.BaseClient._make_api_call", new=mock_api):
            sagemaker = SageMaker(aws_provider)

        assert len(sagemaker.sagemaker_transform_jobs) == 1
        assert sagemaker.sagemaker_transform_jobs[0].volume_kms_key_id is None
        assert sagemaker.sagemaker_transform_jobs[0].detail_fetch_error is None
        assert AWS_REGION_EU_WEST_1 in sagemaker.transform_jobs_scanned_regions

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_PATH}.sagemaker_client", sagemaker),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_transform_job_volume_encrypted_with_cmk.sagemaker_transform_job_volume_encrypted_with_cmk import (
                sagemaker_transform_job_volume_encrypted_with_cmk,
            )

            result = sagemaker_transform_job_volume_encrypted_with_cmk().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    def test_collector_describe_exception_propagates_manual(self):
        """MANUAL path through DescribeTransformJob raising an exception."""

        def mock_api(self, operation_name, kwarg):
            if operation_name == "ListTransformJobs":
                return {
                    "TransformJobSummaries": [
                        {
                            "TransformJobName": test_transform_job,
                            "TransformJobArn": transform_job_arn,
                        }
                    ]
                }
            if operation_name == "DescribeTransformJob":
                raise botocore.exceptions.ClientError(
                    {
                        "Error": {
                            "Code": "AccessDeniedException",
                            "Message": "denied",
                        }
                    },
                    "DescribeTransformJob",
                )
            if operation_name == "ListTags":
                return {"Tags": []}
            if operation_name.startswith("List") or operation_name.startswith(
                "Describe"
            ):
                empty = {
                    "ListNotebookInstances": {"NotebookInstances": []},
                    "ListModels": {"Models": []},
                    "ListTrainingJobs": {"TrainingJobSummaries": []},
                    "ListProcessingJobs": {"ProcessingJobSummaries": []},
                    "ListEndpointConfigs": {"EndpointConfigs": []},
                    "ListDomains": {"Domains": []},
                    "ListModelPackageGroups": {"ModelPackageGroupSummaryList": []},
                    "ListMonitoringSchedules": {"MonitoringScheduleSummaries": []},
                }
                if operation_name in empty:
                    return empty[operation_name]
            return make_api_call(self, operation_name, kwarg)

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        with patch("botocore.client.BaseClient._make_api_call", new=mock_api):
            sagemaker = SageMaker(aws_provider)

        job = sagemaker.sagemaker_transform_jobs[0]
        assert job.volume_kms_key_id is None
        assert job.detail_fetch_error == "ClientError"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_PATH}.sagemaker_client", sagemaker),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_transform_job_volume_encrypted_with_cmk.sagemaker_transform_job_volume_encrypted_with_cmk import (
                sagemaker_transform_job_volume_encrypted_with_cmk,
            )

            result = sagemaker_transform_job_volume_encrypted_with_cmk().execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "ClientError" in result[0].status_extended
