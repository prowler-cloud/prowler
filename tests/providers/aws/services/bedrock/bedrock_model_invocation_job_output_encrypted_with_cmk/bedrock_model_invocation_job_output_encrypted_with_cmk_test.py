from unittest import mock

import botocore
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

JOB_NAME = "test-invocation-job"
JOB_ID = "abc123def456"
JOB_ARN = (
    f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:"
    f"{AWS_ACCOUNT_NUMBER}:model-invocation-job/{JOB_ID}"
)
KMS_KEY_ID = (
    f"arn:aws:kms:{AWS_REGION_US_EAST_1}:" f"{AWS_ACCOUNT_NUMBER}:key/test-key-id"
)


def _model_invocation_job_mock(self, operation_name, kwarg):
    if operation_name == "ListModelInvocationJobs":
        return {
            "invocationJobSummaries": [
                {
                    "jobArn": JOB_ARN,
                    "jobName": JOB_NAME,
                }
            ]
        }

    if operation_name == "GetModelInvocationJob":
        return {
            "jobArn": JOB_ARN,
            "jobName": JOB_NAME,
            "outputDataConfig": {
                "s3OutputDataConfig": {
                    "s3Uri": "s3://test-bucket/output/",
                    "s3EncryptionKeyId": KMS_KEY_ID,
                    "s3BucketOwner": AWS_ACCOUNT_NUMBER,
                }
            },
        }

    return make_api_call(self, operation_name, kwarg)


def _model_invocation_job_without_kms_mock(self, operation_name, kwarg):
    if operation_name == "ListModelInvocationJobs":
        return {
            "invocationJobSummaries": [
                {
                    "jobArn": JOB_ARN,
                    "jobName": JOB_NAME,
                }
            ]
        }

    if operation_name == "GetModelInvocationJob":
        return {
            "jobArn": JOB_ARN,
            "jobName": JOB_NAME,
            "outputDataConfig": {
                "s3OutputDataConfig": {
                    "s3Uri": "s3://test-bucket/output/",
                    "s3BucketOwner": AWS_ACCOUNT_NUMBER,
                }
            },
        }

    return make_api_call(self, operation_name, kwarg)


def _model_invocation_job_get_error_mock(self, operation_name, kwarg):
    if operation_name == "ListModelInvocationJobs":
        return {
            "invocationJobSummaries": [
                {
                    "jobArn": JOB_ARN,
                    "jobName": JOB_NAME,
                }
            ]
        }

    if operation_name == "GetModelInvocationJob":
        raise botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "Access denied",
                }
            },
            operation_name,
        )

    return make_api_call(self, operation_name, kwarg)


def _model_invocation_job_empty_mock(self, operation_name, kwarg):
    if operation_name == "ListModelInvocationJobs":
        return {"invocationJobSummaries": []}

    return make_api_call(self, operation_name, kwarg)


def _model_invocation_job_list_error_mock(self, operation_name, kwarg):
    if operation_name == "ListModelInvocationJobs":
        raise botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "Access denied",
                }
            },
            operation_name,
        )

    return make_api_call(self, operation_name, kwarg)


class Test_bedrock_model_invocation_job_output_encrypted_with_cmk:
    """Unit tests for the Bedrock model invocation job output encryption
    check."""

    def _run(self):
        """Import and execute the check with the mocked Bedrock service."""
        from prowler.providers.aws.services.bedrock.bedrock_service import (
            Bedrock,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                ("prowler.providers.common.provider.Provider." "get_global_provider"),
                return_value=aws_provider,
            ),
            mock.patch(
                (
                    "prowler.providers.aws.services.bedrock."
                    "bedrock_model_invocation_job_output_encrypted_with_cmk."
                    "bedrock_model_invocation_job_output_encrypted_with_cmk."
                    "bedrock_client"
                ),
                new=Bedrock(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_model_invocation_job_output_encrypted_with_cmk.bedrock_model_invocation_job_output_encrypted_with_cmk import (
                bedrock_model_invocation_job_output_encrypted_with_cmk,
            )

            return bedrock_model_invocation_job_output_encrypted_with_cmk().execute()

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_model_invocation_job_mock,
    )
    @mock_aws
    def test_cmk_present_passes(self):
        """A job with an S3 encryption key should pass."""
        result = self._run()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == JOB_NAME
        assert result[0].resource_arn == JOB_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_model_invocation_job_without_kms_mock,
    )
    @mock_aws
    def test_cmk_missing_fails(self):
        """A job without an S3 encryption key should fail."""
        result = self._run()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == JOB_NAME
        assert result[0].resource_arn == JOB_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_model_invocation_job_get_error_mock,
    )
    @mock_aws
    def test_get_job_error_returns_manual(self):
        """A GetModelInvocationJob error should result in a MANUAL finding."""
        result = self._run()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == JOB_NAME
        assert result[0].resource_arn == JOB_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_model_invocation_job_empty_mock,
    )
    @mock_aws
    def test_no_model_invocation_jobs_returns_no_findings(self):
        """No model invocation jobs should result in no findings."""
        result = self._run()

        assert result == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_model_invocation_job_list_error_mock,
    )
    @mock_aws
    def test_list_jobs_error_returns_manual(self):
        """A ListModelInvocationJobs error should result in a MANUAL
        finding."""
        result = self._run()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].resource_id == "model-invocation-job/unknown"
