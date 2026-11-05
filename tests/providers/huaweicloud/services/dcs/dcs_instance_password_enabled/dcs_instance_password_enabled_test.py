from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class Test_dcs_instance_password_enabled:
    def test_dcs_password_enabled(self):
        dcs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.dcs.dcs_instance_password_enabled.dcs_instance_password_enabled.dcs_client",
                new=dcs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.dcs.dcs_service import (
                DCSInstance,
            )
            from prowler.providers.huaweicloud.services.dcs.dcs_instance_password_enabled.dcs_instance_password_enabled import (
                dcs_instance_password_enabled,
            )

            dcs_client.instances = [
                DCSInstance(
                    instance_id="dcs-001",
                    name="redis-secure",
                    status="RUNNING",
                    engine="Redis",
                    no_password_access="false",
                    region="la-south-2",
                ),
            ]
            dcs_client.audited_account = "123456789012"

            check = dcs_instance_password_enabled()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "PASS"
            assert results[0].resource_id == "dcs-001"
            assert "requires password" in results[0].status_extended

    def test_dcs_password_disabled(self):
        dcs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.dcs.dcs_instance_password_enabled.dcs_instance_password_enabled.dcs_client",
                new=dcs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.dcs.dcs_service import (
                DCSInstance,
            )
            from prowler.providers.huaweicloud.services.dcs.dcs_instance_password_enabled.dcs_instance_password_enabled import (
                dcs_instance_password_enabled,
            )

            dcs_client.instances = [
                DCSInstance(
                    instance_id="dcs-002",
                    name="redis-insecure",
                    status="RUNNING",
                    engine="Redis",
                    no_password_access="true",
                    region="la-south-2",
                ),
            ]
            dcs_client.audited_account = "123456789012"

            check = dcs_instance_password_enabled()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "FAIL"
            assert results[0].resource_id == "dcs-002"
            assert "without password" in results[0].status_extended

    def test_dcs_password_mixed(self):
        dcs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.dcs.dcs_instance_password_enabled.dcs_instance_password_enabled.dcs_client",
                new=dcs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.dcs.dcs_service import (
                DCSInstance,
            )
            from prowler.providers.huaweicloud.services.dcs.dcs_instance_password_enabled.dcs_instance_password_enabled import (
                dcs_instance_password_enabled,
            )

            dcs_client.instances = [
                DCSInstance(
                    instance_id="dcs-001",
                    name="redis-secure",
                    status="RUNNING",
                    engine="Redis",
                    no_password_access="false",
                    region="la-south-2",
                ),
                DCSInstance(
                    instance_id="dcs-002",
                    name="redis-insecure",
                    status="RUNNING",
                    engine="Redis",
                    no_password_access="true",
                    region="la-south-2",
                ),
            ]
            dcs_client.audited_account = "123456789012"

            check = dcs_instance_password_enabled()
            results = check.execute()

            assert len(results) == 2
            assert results[0].status == "PASS"
            assert results[1].status == "FAIL"

    def test_dcs_password_empty(self):
        dcs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.dcs.dcs_instance_password_enabled.dcs_instance_password_enabled.dcs_client",
                new=dcs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.dcs.dcs_instance_password_enabled.dcs_instance_password_enabled import (
                dcs_instance_password_enabled,
            )

            dcs_client.instances = []
            dcs_client.audited_account = "123456789012"

            check = dcs_instance_password_enabled()
            results = check.execute()

            assert len(results) == 0
