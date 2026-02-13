from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestRamNoRootAccessKey:
    def test_root_has_keys_fails(self):
        provider = set_mocked_alibabacloud_provider()
        provider.identity.is_root = True
        ram_client = mock.MagicMock()
        ram_client.provider = provider
        ram_client.region = "cn-hangzhou"
        ram_client.audited_account = "1234567890"
        ram_client.root_access_keys = ["AKIA"]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=provider,
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ram.ram_no_root_access_key.ram_no_root_access_key.ram_client",
                new=ram_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ram.ram_no_root_access_key.ram_no_root_access_key import (
                ram_no_root_access_key,
            )

            check = ram_no_root_access_key()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_root_without_keys_passes(self):
        provider = set_mocked_alibabacloud_provider()
        provider.identity.is_root = True
        ram_client = mock.MagicMock()
        ram_client.provider = provider
        ram_client.region = "cn-hangzhou"
        ram_client.audited_account = "1234567890"
        ram_client.root_access_keys = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=provider,
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ram.ram_no_root_access_key.ram_no_root_access_key.ram_client",
                new=ram_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ram.ram_no_root_access_key.ram_no_root_access_key import (
                ram_no_root_access_key,
            )

            check = ram_no_root_access_key()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
