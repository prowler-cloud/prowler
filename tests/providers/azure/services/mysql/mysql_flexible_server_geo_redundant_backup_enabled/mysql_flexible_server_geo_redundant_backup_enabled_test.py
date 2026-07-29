from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.mysql.mysql_service import FlexibleServer
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)


class Test_mysql_flexible_server_geo_redundant_backup_enabled:
    def test_mysql_no_subscriptions(self):
        mysql_client = mock.MagicMock
        mysql_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        mysql_client.flexible_servers = {}

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

            check = mysql_flexible_server_geo_redundant_backup_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_mysql_geo_redundant_backup_disabled(self):
        server_id = str(uuid4())
        server_name = "test-server"
        mysql_client = mock.MagicMock
        mysql_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        mysql_client.flexible_servers = {
            AZURE_SUBSCRIPTION_ID: {
                server_id: FlexibleServer(
                    resource_id=server_id,
                    name=server_name,
                    location="eastus",
                    version="8.0",
                    configurations={},
                    geo_redundant_backup="Disabled",
                )
            }
        }

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

            check = mysql_flexible_server_geo_redundant_backup_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Geo-redundant backup is disabled for server {server_name} in subscription {AZURE_SUBSCRIPTION_DISPLAY}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == server_name
            assert result[0].resource_id == server_id
            assert result[0].location == "eastus"

    def test_mysql_geo_redundant_backup_enabled(self):
        server_id = str(uuid4())
        server_name = "test-server"
        mysql_client = mock.MagicMock
        mysql_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        mysql_client.flexible_servers = {
            AZURE_SUBSCRIPTION_ID: {
                server_id: FlexibleServer(
                    resource_id=server_id,
                    name=server_name,
                    location="eastus",
                    version="8.0",
                    configurations={},
                    geo_redundant_backup="Enabled",
                )
            }
        }

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

            check = mysql_flexible_server_geo_redundant_backup_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Geo-redundant backup is enabled for server {server_name} in subscription {AZURE_SUBSCRIPTION_DISPLAY}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == server_name
            assert result[0].resource_id == server_id
            assert result[0].location == "eastus"
