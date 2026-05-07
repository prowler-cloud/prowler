from unittest import mock

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_mysql_flexible_server_geo_redundant_backup_enabled:
    def test_no_subscriptions(self):
        mysql_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.mysql.mysql_flexible_server_geo_redundant_backup_enabled.mysql_flexible_server_geo_redundant_backup_enabled.mysql_client",
                new=mysql_client,
            ),
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_geo_redundant_backup_enabled.mysql_flexible_server_geo_redundant_backup_enabled import (
                mysql_flexible_server_geo_redundant_backup_enabled,
            )

            mysql_client.flexible_servers = {}

            check = mysql_flexible_server_geo_redundant_backup_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_pass(self):
        mysql_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.mysql.mysql_flexible_server_geo_redundant_backup_enabled.mysql_flexible_server_geo_redundant_backup_enabled.mysql_client",
                new=mysql_client,
            ),
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_geo_redundant_backup_enabled.mysql_flexible_server_geo_redundant_backup_enabled import (
                mysql_flexible_server_geo_redundant_backup_enabled,
            )
            from prowler.providers.azure.services.mysql.mysql_service import FlexibleServer

            mysql_client.flexible_servers = {AZURE_SUBSCRIPTION_ID: {"/sub/rg/item1": FlexibleServer(resource_id="/sub/rg/server1", name="test-server", location="eastus", version="8.0", configurations={}, geo_redundant_backup="Enabled")}}

            check = mysql_flexible_server_geo_redundant_backup_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_fail(self):
        mysql_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.mysql.mysql_flexible_server_geo_redundant_backup_enabled.mysql_flexible_server_geo_redundant_backup_enabled.mysql_client",
                new=mysql_client,
            ),
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_geo_redundant_backup_enabled.mysql_flexible_server_geo_redundant_backup_enabled import (
                mysql_flexible_server_geo_redundant_backup_enabled,
            )
            from prowler.providers.azure.services.mysql.mysql_service import FlexibleServer

            mysql_client.flexible_servers = {AZURE_SUBSCRIPTION_ID: {"/sub/rg/item1": FlexibleServer(resource_id="/sub/rg/server1", name="test-server", location="eastus", version="8.0", configurations={}, geo_redundant_backup="Disabled")}}

            check = mysql_flexible_server_geo_redundant_backup_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
