from re import search
from unittest import mock

from prowler.providers.aws.services.glue.glue_service import Job, SecurityConfig
from tests.providers.aws.utils import AWS_REGION_US_EAST_1


class Test_glue_etl_jobs_amazon_s3_encryption_enabled:
    def test_glue_no_jobs(self):
        glue_client = mock.MagicMock
        glue_client.jobs = []

        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_etl_jobs_amazon_s3_encryption_enabled.glue_etl_jobs_amazon_s3_encryption_enabled import (
                glue_etl_jobs_amazon_s3_encryption_enabled,
            )

            check = glue_etl_jobs_amazon_s3_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_glue_encrypted_job(self):
        glue_client = mock.MagicMock
        glue_client.jobs = [
            Job(
                name="test",
                security="sec_config",
                arguments=None,
                region=AWS_REGION_US_EAST_1,
                arn="arn_test",
            )
        ]
        glue_client.security_configs = [
            SecurityConfig(
                name="sec_config",
                s3_encryption="SSE-KMS",
                s3_key_arn="key_arn",
                cw_encryption="DISABLED",
                jb_encryption="DISABLED",
                region=AWS_REGION_US_EAST_1,
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_etl_jobs_amazon_s3_encryption_enabled.glue_etl_jobs_amazon_s3_encryption_enabled import (
                glue_etl_jobs_amazon_s3_encryption_enabled,
            )

            check = glue_etl_jobs_amazon_s3_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "has S3 encryption enabled with key",
                result[0].status_extended,
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == "arn_test"

    def test_glue_unencrypted_job(self):
        glue_client = mock.MagicMock
        glue_client.jobs = [
            Job(
                name="test",
                security="sec_config",
                arguments=None,
                region=AWS_REGION_US_EAST_1,
                arn="arn_test",
            )
        ]
        glue_client.security_configs = [
            SecurityConfig(
                name="sec_config",
                s3_encryption="DISABLED",
                cw_encryption="DISABLED",
                jb_encryption="DISABLED",
                region=AWS_REGION_US_EAST_1,
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_etl_jobs_amazon_s3_encryption_enabled.glue_etl_jobs_amazon_s3_encryption_enabled import (
                glue_etl_jobs_amazon_s3_encryption_enabled,
            )

            check = glue_etl_jobs_amazon_s3_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "does not have S3 encryption enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == "arn_test"

    def test_glue_no_sec_configs(self):
        glue_client = mock.MagicMock
        glue_client.jobs = [
            Job(
                name="test",
                security="sec_config",
                region=AWS_REGION_US_EAST_1,
                arn="arn_test",
            )
        ]
        glue_client.security_configs = []

        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_etl_jobs_amazon_s3_encryption_enabled.glue_etl_jobs_amazon_s3_encryption_enabled import (
                glue_etl_jobs_amazon_s3_encryption_enabled,
            )

            check = glue_etl_jobs_amazon_s3_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "does not have security configuration",
                result[0].status_extended,
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == "arn_test"

    def test_glue_encrypted_job_with_argument(self):
        glue_client = mock.MagicMock
        glue_client.jobs = [
            Job(
                name="test",
                security="sec_config",
                arguments={
                    "--encryption-type": "sse-s3",
                    "--enable-job-insights": "false",
                },
                region=AWS_REGION_US_EAST_1,
                arn="arn_test",
            )
        ]
        glue_client.security_configs = []

        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_etl_jobs_amazon_s3_encryption_enabled.glue_etl_jobs_amazon_s3_encryption_enabled import (
                glue_etl_jobs_amazon_s3_encryption_enabled,
            )

            check = glue_etl_jobs_amazon_s3_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "has S3 encryption enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == "arn_test"
