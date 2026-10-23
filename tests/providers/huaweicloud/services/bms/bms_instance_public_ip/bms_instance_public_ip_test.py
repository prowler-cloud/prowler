from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestBmsInstancePublicIp:
    def test_instance_with_public_ip_fails(self):
        bms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.bms.bms_instance_public_ip.bms_instance_public_ip.bms_client",
                new=bms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.bms.bms_instance_public_ip.bms_instance_public_ip import (
                bms_instance_public_ip,
            )
            from prowler.providers.huaweicloud.services.bms.bms_service import (
                BareMetalServer,
            )

            server = BareMetalServer(
                id="bms-1",
                name="bms-public",
                region="la-south-2",
                status="ACTIVE",
                public_ip="123.45.67.89",
            )
            bms_client.servers = {server.id: server}
            bms_client.audited_account = "123456789012"

            check = bms_instance_public_ip()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "123.45.67.89" in result[0].status_extended

    def test_instance_without_public_ip_passes(self):
        bms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.bms.bms_instance_public_ip.bms_instance_public_ip.bms_client",
                new=bms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.bms.bms_instance_public_ip.bms_instance_public_ip import (
                bms_instance_public_ip,
            )
            from prowler.providers.huaweicloud.services.bms.bms_service import (
                BareMetalServer,
            )

            server = BareMetalServer(
                id="bms-2",
                name="bms-private",
                region="la-south-2",
                status="ACTIVE",
                public_ip="",
            )
            bms_client.servers = {server.id: server}
            bms_client.audited_account = "123456789012"

            check = bms_instance_public_ip()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "does not have a public IP" in result[0].status_extended

    def test_no_instances(self):
        bms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.bms.bms_instance_public_ip.bms_instance_public_ip.bms_client",
                new=bms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.bms.bms_instance_public_ip.bms_instance_public_ip import (
                bms_instance_public_ip,
            )

            bms_client.servers = {}
            bms_client.audited_account = "123456789012"

            check = bms_instance_public_ip()
            result = check.execute()

            assert len(result) == 0
