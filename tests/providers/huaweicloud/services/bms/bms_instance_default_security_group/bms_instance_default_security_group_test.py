from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestBmsInstanceDefaultSecurityGroup:
    def test_instance_with_default_sg_fails(self):
        bms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.bms.bms_instance_default_security_group.bms_instance_default_security_group.bms_client",
                new=bms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.bms.bms_instance_default_security_group.bms_instance_default_security_group import (
                bms_instance_default_security_group,
            )
            from prowler.providers.huaweicloud.services.bms.bms_service import (
                BareMetalServer,
            )

            server = BareMetalServer(
                id="bms-1",
                name="bms-default-sg",
                region="la-south-2",
                status="ACTIVE",
                security_groups={"sg-001": "default"},
            )
            bms_client.servers = {server.id: server}
            bms_client.audited_account = "123456789012"

            check = bms_instance_default_security_group()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "default security group" in result[0].status_extended

    def test_instance_with_sys_default_sg_fails(self):
        bms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.bms.bms_instance_default_security_group.bms_instance_default_security_group.bms_client",
                new=bms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.bms.bms_instance_default_security_group.bms_instance_default_security_group import (
                bms_instance_default_security_group,
            )
            from prowler.providers.huaweicloud.services.bms.bms_service import (
                BareMetalServer,
            )

            server = BareMetalServer(
                id="bms-2",
                name="bms-sys-default-sg",
                region="la-south-2",
                status="ACTIVE",
                security_groups={"sg-002": "sys_default"},
            )
            bms_client.servers = {server.id: server}
            bms_client.audited_account = "123456789012"

            check = bms_instance_default_security_group()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "default security group" in result[0].status_extended

    def test_instance_with_custom_sg_passes(self):
        bms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.bms.bms_instance_default_security_group.bms_instance_default_security_group.bms_client",
                new=bms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.bms.bms_instance_default_security_group.bms_instance_default_security_group import (
                bms_instance_default_security_group,
            )
            from prowler.providers.huaweicloud.services.bms.bms_service import (
                BareMetalServer,
            )

            server = BareMetalServer(
                id="bms-3",
                name="bms-custom-sg",
                region="la-south-2",
                status="ACTIVE",
                security_groups={"sg-003": "web-sg"},
            )
            bms_client.servers = {server.id: server}
            bms_client.audited_account = "123456789012"

            check = bms_instance_default_security_group()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "not using the default security group" in result[0].status_extended

    def test_no_instances(self):
        bms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.bms.bms_instance_default_security_group.bms_instance_default_security_group.bms_client",
                new=bms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.bms.bms_instance_default_security_group.bms_instance_default_security_group import (
                bms_instance_default_security_group,
            )

            bms_client.servers = {}
            bms_client.audited_account = "123456789012"

            check = bms_instance_default_security_group()
            result = check.execute()

            assert len(result) == 0
