from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class Test_cbr_vault_resources:
    def test_cbr_vault_resources_pass(self):
        cbr_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cbr.cbr_vault_resources.cbr_vault_resources.cbr_client",
                new=cbr_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cbr.cbr_service import (
                CBRVault,
            )
            from prowler.providers.huaweicloud.services.cbr.cbr_vault_resources.cbr_vault_resources import (
                cbr_vault_resources,
            )

            cbr_client.vaults = [
                CBRVault(
                    vault_id="cbr-001",
                    name="vault-with-resources",
                    resources=["resource-1", "resource-2"],
                    region="la-south-2",
                ),
            ]
            cbr_client.audited_account = "123456789012"

            check = cbr_vault_resources()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "PASS"
            assert results[0].resource_id == "cbr-001"
            assert "2 resource(s)" in results[0].status_extended

    def test_cbr_vault_resources_fail(self):
        cbr_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cbr.cbr_vault_resources.cbr_vault_resources.cbr_client",
                new=cbr_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cbr.cbr_service import (
                CBRVault,
            )
            from prowler.providers.huaweicloud.services.cbr.cbr_vault_resources.cbr_vault_resources import (
                cbr_vault_resources,
            )

            cbr_client.vaults = [
                CBRVault(
                    vault_id="cbr-002",
                    name="vault-empty",
                    resources=[],
                    region="la-south-2",
                ),
            ]
            cbr_client.audited_account = "123456789012"

            check = cbr_vault_resources()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "FAIL"
            assert results[0].resource_id == "cbr-002"
            assert "no resources" in results[0].status_extended

    def test_cbr_vault_resources_mixed(self):
        cbr_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cbr.cbr_vault_resources.cbr_vault_resources.cbr_client",
                new=cbr_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cbr.cbr_service import (
                CBRVault,
            )
            from prowler.providers.huaweicloud.services.cbr.cbr_vault_resources.cbr_vault_resources import (
                cbr_vault_resources,
            )

            cbr_client.vaults = [
                CBRVault(
                    vault_id="cbr-001",
                    name="vault-with-resources",
                    resources=["resource-1"],
                    region="la-south-2",
                ),
                CBRVault(
                    vault_id="cbr-002",
                    name="vault-empty",
                    resources=[],
                    region="la-south-2",
                ),
            ]
            cbr_client.audited_account = "123456789012"

            check = cbr_vault_resources()
            results = check.execute()

            assert len(results) == 2
            assert results[0].status == "PASS"
            assert results[1].status == "FAIL"

    def test_cbr_vault_resources_empty(self):
        cbr_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cbr.cbr_vault_resources.cbr_vault_resources.cbr_client",
                new=cbr_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cbr.cbr_vault_resources.cbr_vault_resources import (
                cbr_vault_resources,
            )

            cbr_client.vaults = []
            cbr_client.audited_account = "123456789012"

            check = cbr_vault_resources()
            results = check.execute()

            assert len(results) == 0
