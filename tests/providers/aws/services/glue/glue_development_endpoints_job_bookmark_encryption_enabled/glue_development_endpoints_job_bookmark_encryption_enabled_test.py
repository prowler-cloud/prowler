from unittest.mock import MagicMock, patch

from prowler.providers.aws.services.glue.glue_service import DevEndpoint, SecurityConfig
from tests.providers.aws.utils import AWS_REGION_US_EAST_1


class Test_glue_development_endpoints_job_bookmark_encryption_enabled:
    def test_glue_no_endpoints(self):
        glue_client = MagicMock
        glue_client.dev_endpoints = []

        with patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            new=glue_client,
        ), patch(
            "prowler.providers.aws.services.glue.glue_client.glue_client",
            new=glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_development_endpoints_job_bookmark_encryption_enabled.glue_development_endpoints_job_bookmark_encryption_enabled import (
                glue_development_endpoints_job_bookmark_encryption_enabled,
            )

            check = glue_development_endpoints_job_bookmark_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_glue_encrypted_endpoint(self):
        glue_client = MagicMock
        glue_client.dev_endpoints = [
            DevEndpoint(
                name="test",
                security="sec_config",
                region=AWS_REGION_US_EAST_1,
                arn="arn_test",
                tags=[{"test": "value"}],
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

        with patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            new=glue_client,
        ), patch(
            "prowler.providers.aws.services.glue.glue_client.glue_client",
            new=glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_development_endpoints_job_bookmark_encryption_enabled.glue_development_endpoints_job_bookmark_encryption_enabled import (
                glue_development_endpoints_job_bookmark_encryption_enabled,
            )

            check = glue_development_endpoints_job_bookmark_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Glue development endpoint test has Job Bookmark encryption enabled with key key_arn."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == "arn_test"
            assert result[0].resource_tags == [{"test": "value"}]

    def test_glue_unencrypted_endpoint(self):
        glue_client = MagicMock
        glue_client.dev_endpoints = [
            DevEndpoint(
                name="test",
                security="sec_config",
                region=AWS_REGION_US_EAST_1,
                arn="arn_test",
                tags=[{"test": "value"}],
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

        with patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            new=glue_client,
        ), patch(
            "prowler.providers.aws.services.glue.glue_client.glue_client",
            new=glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_development_endpoints_job_bookmark_encryption_enabled.glue_development_endpoints_job_bookmark_encryption_enabled import (
                glue_development_endpoints_job_bookmark_encryption_enabled,
            )

            check = glue_development_endpoints_job_bookmark_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Glue development endpoint test does not have Job Bookmark encryption enabled."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == "arn_test"
            assert result[0].resource_tags == [{"test": "value"}]

    def test_glue_no_sec_configs(self):
        glue_client = MagicMock
        glue_client.dev_endpoints = [
            DevEndpoint(
                name="test",
                security="sec_config",
                region=AWS_REGION_US_EAST_1,
                arn="arn_test",
                tags=[{"test": "value"}],
            )
        ]
        glue_client.security_configs = []

        with patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            new=glue_client,
        ), patch(
            "prowler.providers.aws.services.glue.glue_client.glue_client",
            new=glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_development_endpoints_job_bookmark_encryption_enabled.glue_development_endpoints_job_bookmark_encryption_enabled import (
                glue_development_endpoints_job_bookmark_encryption_enabled,
            )

            check = glue_development_endpoints_job_bookmark_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Glue development endpoint test does not have security configuration."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == "arn_test"
            assert result[0].resource_tags == [{"test": "value"}]
