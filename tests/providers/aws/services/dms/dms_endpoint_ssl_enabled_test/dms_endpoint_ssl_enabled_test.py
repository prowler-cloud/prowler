from unittest import mock

from prowler.providers.aws.services.dms.dms_service import Endpoint
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_dms_endpoint_ssl_enabled:
    def test_dms_no_endpoints(self):
        dms_client = mock.MagicMock
        dms_client.endpoints = {}

        with mock.patch(
            "prowler.providers.aws.services.dms.dms_service.DMS",
            new=dms_client,
        ), mock.patch(
            "prowler.providers.aws.services.dms.dms_client.dms_client",
            new=dms_client,
        ):
            from prowler.providers.aws.services.dms.dms_endpoint_ssl_enabled.dms_endpoint_ssl_enabled import (
                dms_endpoint_ssl_enabled,
            )

            check = dms_endpoint_ssl_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_dms_endpoint_ssl_none(self):
        dms_client = mock.MagicMock
        endpoint_arn = f"arn:aws:dms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:endpoint:test-endpoint-no-ssl"
        dms_client.endpoints = {
            endpoint_arn: Endpoint(
                arn=endpoint_arn,
                id="test-endpoint-no-ssl",
                mongodb_auth_type="no",
                engine_name="test-engine",
                redis_ssl_protocol="plaintext",
                region=AWS_REGION_US_EAST_1,
                ssl_mode="none",
                tags=[{"Key": "Name", "Value": "test-endpoint-no-ssl"}],
            )
        }
        dms_client.audited_account = AWS_ACCOUNT_NUMBER
        dms_client.audited_partition = "aws"
        dms_client.audited_region = AWS_REGION_US_EAST_1

        with mock.patch(
            "prowler.providers.aws.services.dms.dms_service.DMS",
            new=dms_client,
        ), mock.patch(
            "prowler.providers.aws.services.dms.dms_client.dms_client",
            new=dms_client,
        ):
            from prowler.providers.aws.services.dms.dms_endpoint_ssl_enabled.dms_endpoint_ssl_enabled import (
                dms_endpoint_ssl_enabled,
            )

            check = dms_endpoint_ssl_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "test-endpoint-no-ssl"
            assert (
                result[0].resource_arn
                == f"arn:aws:dms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:endpoint:test-endpoint-no-ssl"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].status_extended
                == "DMS Endpoint test-endpoint-no-ssl is not using SSL."
            )
            assert result[0].resource_tags == [
                {"Key": "Name", "Value": "test-endpoint-no-ssl"}
            ]

    def test_dms_endpoint_ssl_require(self):
        dms_client = mock.MagicMock
        endpoint_arn = f"arn:aws:dms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:endpoint:test-endpoint-ssl-require"
        dms_client.endpoints = {
            endpoint_arn: Endpoint(
                arn=endpoint_arn,
                id="test-endpoint-ssl-require",
                mongodb_auth_type="no",
                engine_name="test-engine",
                redis_ssl_protocol="plaintext",
                region=AWS_REGION_US_EAST_1,
                ssl_mode="require",
                tags=[{"Key": "Name", "Value": "test-endpoint-ssl-require"}],
            )
        }
        dms_client.audited_account = AWS_ACCOUNT_NUMBER
        dms_client.audited_partition = "aws"
        dms_client.audited_region = AWS_REGION_US_EAST_1

        with mock.patch(
            "prowler.providers.aws.services.dms.dms_service.DMS",
            new=dms_client,
        ), mock.patch(
            "prowler.providers.aws.services.dms.dms_client.dms_client",
            new=dms_client,
        ):
            from prowler.providers.aws.services.dms.dms_endpoint_ssl_enabled.dms_endpoint_ssl_enabled import (
                dms_endpoint_ssl_enabled,
            )

            check = dms_endpoint_ssl_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "test-endpoint-ssl-require"
            assert result[0].resource_arn == endpoint_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].status_extended
                == "DMS Endpoint test-endpoint-ssl-require is using SSL with mode: require."
            )
            assert result[0].resource_tags == [
                {"Key": "Name", "Value": "test-endpoint-ssl-require"}
            ]

    def test_dms_endpoint_ssl_verify_ca(self):
        dms_client = mock.MagicMock
        endpoint_arn = f"arn:aws:dms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:endpoint:test-endpoint-ssl-verify-ca"
        dms_client.endpoints = {
            endpoint_arn: Endpoint(
                arn=endpoint_arn,
                id="test-endpoint-ssl-verify-ca",
                engine_name="test-engine",
                mongodb_auth_type="no",
                redis_ssl_protocol="plaintext",
                region=AWS_REGION_US_EAST_1,
                ssl_mode="verify-ca",
                tags=[{"Key": "Name", "Value": "test-endpoint-ssl-verify-ca"}],
            )
        }
        dms_client.audited_account = AWS_ACCOUNT_NUMBER
        dms_client.audited_partition = "aws"
        dms_client.audited_region = AWS_REGION_US_EAST_1

        with mock.patch(
            "prowler.providers.aws.services.dms.dms_service.DMS",
            new=dms_client,
        ), mock.patch(
            "prowler.providers.aws.services.dms.dms_client.dms_client",
            new=dms_client,
        ):
            from prowler.providers.aws.services.dms.dms_endpoint_ssl_enabled.dms_endpoint_ssl_enabled import (
                dms_endpoint_ssl_enabled,
            )

            check = dms_endpoint_ssl_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "test-endpoint-ssl-verify-ca"
            assert result[0].resource_arn == endpoint_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].status_extended
                == "DMS Endpoint test-endpoint-ssl-verify-ca is using SSL with mode: verify-ca."
            )
            assert result[0].resource_tags == [
                {"Key": "Name", "Value": "test-endpoint-ssl-verify-ca"}
            ]

    def test_dms_endpoint_ssl_verify_full(self):
        dms_client = mock.MagicMock
        endpoint_arn = f"arn:aws:dms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:endpoint:test-endpoint-ssl-verify-full"
        dms_client.endpoints = {
            endpoint_arn: Endpoint(
                arn=endpoint_arn,
                id="test-endpoint-ssl-verify-full",
                mongodb_auth_type="no",
                engine_name="test-engine",
                redis_ssl_protocol="plaintext",
                region=AWS_REGION_US_EAST_1,
                ssl_mode="verify-full",
                tags=[{"Key": "Name", "Value": "test-endpoint-ssl-verify-full"}],
            )
        }
        dms_client.audited_account = AWS_ACCOUNT_NUMBER
        dms_client.audited_partition = "aws"
        dms_client.audited_region = AWS_REGION_US_EAST_1

        with mock.patch(
            "prowler.providers.aws.services.dms.dms_service.DMS",
            new=dms_client,
        ), mock.patch(
            "prowler.providers.aws.services.dms.dms_client.dms_client",
            new=dms_client,
        ):
            from prowler.providers.aws.services.dms.dms_endpoint_ssl_enabled.dms_endpoint_ssl_enabled import (
                dms_endpoint_ssl_enabled,
            )

            check = dms_endpoint_ssl_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "test-endpoint-ssl-verify-full"
            assert result[0].resource_arn == endpoint_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].status_extended
                == "DMS Endpoint test-endpoint-ssl-verify-full is using SSL with mode: verify-full."
            )
            assert result[0].resource_tags == [
                {"Key": "Name", "Value": "test-endpoint-ssl-verify-full"}
            ]
