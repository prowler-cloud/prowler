from unittest.mock import MagicMock, patch

from prowler.providers.aws.services.lightsail.lightsail_service import StaticIP
from tests.providers.aws.utils import (
    AWS_REGION_US_EAST_1,
    AWS_REGION_US_EAST_1_AZA,
    BASE_LIGHTSAIL_ARN,
    set_mocked_aws_provider,
)


class Test_lightsail_static_ip_unused:
    def test_lightsail_no_statics_ips(self):
        lightsail_client = MagicMock
        lightsail_client.static_ips = {}

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), patch(
            "prowler.providers.aws.services.lightsail.lightsail_service.Lightsail",
            new=lightsail_client,
        ):
            from prowler.providers.aws.services.lightsail.lightsail_static_ip_unused.lightsail_static_ip_unused import (
                lightsail_static_ip_unused,
            )

            check = lightsail_static_ip_unused()
            result = check.execute()

            assert len(result) == 0

    def test_lightsail_static_ip_unused(self):
        lightsail_client = MagicMock
        lightsail_client.static_ips = {
            f"{BASE_LIGHTSAIL_ARN}:StaticIp/test-static-ip": StaticIP(
                name="test-static-ip",
                id="1234/5678",
                region=AWS_REGION_US_EAST_1,
                availability_zone=AWS_REGION_US_EAST_1_AZA,
                ip_address="1.2.3.4",
                is_attached=False,
                attached_to="",
            )
        }

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), patch(
            "prowler.providers.aws.services.lightsail.lightsail_service.Lightsail",
            new=lightsail_client,
        ):
            from prowler.providers.aws.services.lightsail.lightsail_static_ip_unused.lightsail_static_ip_unused import (
                lightsail_static_ip_unused,
            )

            check = lightsail_static_ip_unused()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Static IP 'test-static-ip' is not associated with any instance."
            )
            assert result[0].resource_id == "1234/5678"
            assert (
                result[0].resource_arn
                == f"{BASE_LIGHTSAIL_ARN}:StaticIp/test-static-ip"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_lightsail_static_ip_attached(self):
        lightsail_client = MagicMock
        lightsail_client.static_ips = {
            f"{BASE_LIGHTSAIL_ARN}:StaticIp/test-static-ip": StaticIP(
                name="test-static-ip",
                id="1234/5678",
                region=AWS_REGION_US_EAST_1,
                availability_zone=AWS_REGION_US_EAST_1_AZA,
                ip_address="1.2.3.4",
                is_attached=True,
                attached_to="test-instance",
            )
        }

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), patch(
            "prowler.providers.aws.services.lightsail.lightsail_service.Lightsail",
            new=lightsail_client,
        ):
            from prowler.providers.aws.services.lightsail.lightsail_static_ip_unused.lightsail_static_ip_unused import (
                lightsail_static_ip_unused,
            )

            check = lightsail_static_ip_unused()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Static IP 'test-static-ip' is associated with the instance 'test-instance'."
            )
            assert result[0].resource_id == "1234/5678"
            assert (
                result[0].resource_arn
                == f"{BASE_LIGHTSAIL_ARN}:StaticIp/test-static-ip"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1
