from re import search
from unittest import mock

from prowler.providers.aws.services.glue.glue_service import DevEndpoint, SecurityConfig
from tests.providers.aws.audit_info_utils import AWS_REGION_US_EAST_1


class Test_glue_development_endpoints_job_bookmark_encryption_enabled:
    def test_glue_no_endpoints(self):
        glue_client = mock.MagicMock
        glue_client.dev_endpoints = []

        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_development_endpoints_job_bookmark_encryption_enabled.glue_development_endpoints_job_bookmark_encryption_enabled import (
                glue_development_endpoints_job_bookmark_encryption_enabled,
            )

            check = glue_development_endpoints_job_bookmark_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_glue_encrypted_endpoint(self):
        glue_client = mock.MagicMock
        glue_client.dev_endpoints = [
            DevEndpoint(
                name="test",
                security="sec_config",
                region=AWS_REGION_US_EAST_1,
                arn="arn_test",
            )
        ]
        glue_client.security_configs = [
            SecurityConfig(
                name="sec_config",
                jb_encryption="SSE-KMS",
                jb_key_arn="key_arn",
                cw_encryption="DISABLED",
                s3_encryption="DISABLED",
                region=AWS_REGION_US_EAST_1,
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_development_endpoints_job_bookmark_encryption_enabled.glue_development_endpoints_job_bookmark_encryption_enabled import (
                glue_development_endpoints_job_bookmark_encryption_enabled,
            )

            check = glue_development_endpoints_job_bookmark_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "has Job Bookmark encryption enabled with key",
                result[0].status_extended,
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == "arn_test"

    def test_glue_unencrypted_endpoint(self):
        glue_client = mock.MagicMock
        glue_client.dev_endpoints = [
            DevEndpoint(
                name="test",
                security="sec_config",
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
            from prowler.providers.aws.services.glue.glue_development_endpoints_job_bookmark_encryption_enabled.glue_development_endpoints_job_bookmark_encryption_enabled import (
                glue_development_endpoints_job_bookmark_encryption_enabled,
            )

            check = glue_development_endpoints_job_bookmark_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "does not have Job Bookmark encryption enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == "arn_test"

    def test_glue_no_sec_configs(self):
        glue_client = mock.MagicMock
        glue_client.dev_endpoints = [
            DevEndpoint(
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
            from prowler.providers.aws.services.glue.glue_development_endpoints_job_bookmark_encryption_enabled.glue_development_endpoints_job_bookmark_encryption_enabled import (
                glue_development_endpoints_job_bookmark_encryption_enabled,
            )

            check = glue_development_endpoints_job_bookmark_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "does not have security configuration",
                result[0].status_extended,
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == "arn_test"
