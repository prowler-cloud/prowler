from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    set_mocked_alibabacloud_provider,
)


class Test_ram_root_access_keys_absent:
    def test_ram_root_access_keys_absent_pass(self):
        ram_client = mock.MagicMock
        ram_client.account_id = ALIBABACLOUD_ACCOUNT_ID
        ram_client.root_has_access_keys = False

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ram.ram_root_access_keys_absent.ram_root_access_keys_absent.ram_client",
            new=ram_client,
        ):
            from prowler.providers.alibabacloud.services.ram.ram_root_access_keys_absent.ram_root_access_keys_absent import (
                ram_root_access_keys_absent,
            )

            check = ram_root_access_keys_absent()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "root-account"
            assert result[0].account_uid == ALIBABACLOUD_ACCOUNT_ID
            assert result[0].region == "global"
            assert "access keys" in result[0].status_extended.lower()

    def test_ram_root_access_keys_absent_fail(self):
        ram_client = mock.MagicMock
        ram_client.account_id = ALIBABACLOUD_ACCOUNT_ID
        ram_client.root_has_access_keys = True

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ram.ram_root_access_keys_absent.ram_root_access_keys_absent.ram_client",
            new=ram_client,
        ):
            from prowler.providers.alibabacloud.services.ram.ram_root_access_keys_absent.ram_root_access_keys_absent import (
                ram_root_access_keys_absent,
            )

            check = ram_root_access_keys_absent()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "root-account"
