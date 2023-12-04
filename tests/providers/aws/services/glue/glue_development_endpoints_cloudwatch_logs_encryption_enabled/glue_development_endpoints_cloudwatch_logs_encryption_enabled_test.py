from re import search
from unittest import mock

from prowler.providers.aws.services.glue.glue_service import DevEndpoint, SecurityConfig
from tests.providers.aws.audit_info_utils import AWS_REGION_EU_WEST_1


class Test_glue_development_endpoints_cloudwatch_logs_encryption_enabled:
    def test_glue_no_endpoints(self):
        glue_client = mock.MagicMock
        glue_client.dev_endpoints = []

        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_development_endpoints_cloudwatch_logs_encryption_enabled.glue_development_endpoints_cloudwatch_logs_encryption_enabled import (
                glue_development_endpoints_cloudwatch_logs_encryption_enabled,
            )

            check = glue_development_endpoints_cloudwatch_logs_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_glue_encrypted_endpoint(self):
        glue_client = mock.MagicMock
        glue_client.dev_endpoints = [
            DevEndpoint(
                name="test",
                security="sec_config",
                region=AWS_REGION_EU_WEST_1,
                arn="arn_test",
            )
        ]
        glue_client.security_configs = [
            SecurityConfig(
                name="sec_config",
                cw_encryption="SSE-KMS",
                cw_key_arn="key_arn",
                s3_encryption="DISABLED",
                jb_encryption="DISABLED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_development_endpoints_cloudwatch_logs_encryption_enabled.glue_development_endpoints_cloudwatch_logs_encryption_enabled import (
                glue_development_endpoints_cloudwatch_logs_encryption_enabled,
            )

            check = glue_development_endpoints_cloudwatch_logs_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "has CloudWatch logs encryption enabled with key",
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
                region=AWS_REGION_EU_WEST_1,
                arn="arn_test",
            )
        ]
        glue_client.security_configs = [
            SecurityConfig(
                name="sec_config",
                s3_encryption="DISABLED",
                cw_encryption="DISABLED",
                jb_encryption="DISABLED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_development_endpoints_cloudwatch_logs_encryption_enabled.glue_development_endpoints_cloudwatch_logs_encryption_enabled import (
                glue_development_endpoints_cloudwatch_logs_encryption_enabled,
            )

            check = glue_development_endpoints_cloudwatch_logs_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "does not have CloudWatch logs encryption enabled",
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
                region=AWS_REGION_EU_WEST_1,
                arn="arn_test",
            )
        ]
        glue_client.security_configs = []

        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_development_endpoints_cloudwatch_logs_encryption_enabled.glue_development_endpoints_cloudwatch_logs_encryption_enabled import (
                glue_development_endpoints_cloudwatch_logs_encryption_enabled,
            )

            check = glue_development_endpoints_cloudwatch_logs_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "does not have security configuration",
                result[0].status_extended,
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == "arn_test"
