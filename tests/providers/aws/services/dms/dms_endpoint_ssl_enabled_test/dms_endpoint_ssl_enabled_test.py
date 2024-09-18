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
        ):
            from prowler.providers.aws.services.dms.dms_endpoint_ssl_enabled.dms_endpoint_ssl_enabled import (
                dms_endpoint_ssl_enabled,
            )

            check = dms_endpoint_ssl_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_dms_endpoint_ssl_none(self):
        dms_client = mock.MagicMock
        dms_client.endpoints = {
            "test-endpoint-no-ssl": Endpoint(id="test-endpoint-no-ssl", ssl_mode="none")
        }
        dms_client.audited_account = AWS_ACCOUNT_NUMBER
        dms_client.audited_partition = "aws"
        dms_client.audited_region = AWS_REGION_US_EAST_1

        with mock.patch(
            "prowler.providers.aws.services.dms.dms_service.DMS",
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
            assert result[0].resource_arn == "test-endpoint-no-ssl"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].status_extended
                == "DMS Endpoint test-endpoint-no-ssl is not using SSL."
            )

    def test_dms_endpoint_ssl_require(self):
        dms_client = mock.MagicMock
        dms_client.endpoints = {
            "test-endpoint-ssl-require": Endpoint(
                id="test-endpoint-ssl-require", ssl_mode="require"
            )
        }
        dms_client.audited_account = AWS_ACCOUNT_NUMBER
        dms_client.audited_partition = "aws"
        dms_client.audited_region = AWS_REGION_US_EAST_1

        with mock.patch(
            "prowler.providers.aws.services.dms.dms_service.DMS",
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
            assert result[0].resource_arn == "test-endpoint-ssl-require"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].status_extended
                == "DMS Endpoint test-endpoint-ssl-require is using SSL with mode: require."
            )

    def test_dms_endpoint_ssl_verify_ca(self):
        dms_client = mock.MagicMock
        dms_client.endpoints = {
            "test-endpoint-ssl-verify-ca": Endpoint(
                id="test-endpoint-ssl-verify-ca", ssl_mode="verify-ca"
            )
        }
        dms_client.audited_account = AWS_ACCOUNT_NUMBER
        dms_client.audited_partition = "aws"
        dms_client.audited_region = AWS_REGION_US_EAST_1

        with mock.patch(
            "prowler.providers.aws.services.dms.dms_service.DMS",
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
            assert result[0].resource_arn == "test-endpoint-ssl-verify-ca"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].status_extended
                == "DMS Endpoint test-endpoint-ssl-verify-ca is using SSL with mode: verify-ca."
            )

    def test_dms_endpoint_ssl_verify_full(self):
        dms_client = mock.MagicMock
        dms_client.endpoints = {
            "test-endpoint-ssl-verify-full": Endpoint(
                id="test-endpoint-ssl-verify-full", ssl_mode="verify-full"
            )
        }
        dms_client.audited_account = AWS_ACCOUNT_NUMBER
        dms_client.audited_partition = "aws"
        dms_client.audited_region = AWS_REGION_US_EAST_1

        with mock.patch(
            "prowler.providers.aws.services.dms.dms_service.DMS",
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
            assert result[0].resource_arn == "test-endpoint-ssl-verify-full"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].status_extended
                == "DMS Endpoint test-endpoint-ssl-verify-full is using SSL with mode: verify-full."
            )
