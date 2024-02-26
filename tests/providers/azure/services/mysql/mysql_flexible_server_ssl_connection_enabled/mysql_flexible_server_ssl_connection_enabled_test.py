from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.mysql.mysql_service import (
    Configuration,
    FlexibleServer,
)
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION


class Test_mysql_flexible_server_ssl_connection_enabled:
    def test_mysql_no_subscriptions(self):
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {}

        with mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_ssl_connection_enabled.mysql_flexible_server_ssl_connection_enabled.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_ssl_connection_enabled.mysql_flexible_server_ssl_connection_enabled import (
                mysql_flexible_server_ssl_connection_enabled,
            )

            check = mysql_flexible_server_ssl_connection_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_mysql_no_servers(self):
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {AZURE_SUBSCRIPTION: {}}

        with mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_ssl_connection_enabled.mysql_flexible_server_ssl_connection_enabled.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_ssl_connection_enabled.mysql_flexible_server_ssl_connection_enabled import (
                mysql_flexible_server_ssl_connection_enabled,
            )

            check = mysql_flexible_server_ssl_connection_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_mysql_connection_enabled(self):
        server_name = str(uuid4())
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {
            AZURE_SUBSCRIPTION: {
                server_name: FlexibleServer(
                    resource_id="/subscriptions/resource_id",
                    location="location",
                    version="version",
                    configurations={
                        "require_secure_transport": Configuration(
                            resource_id=f"/subscriptions/{server_name}/configurations/require_secure_transport",
                            description="description",
                            value="ON",
                        )
                    },
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_ssl_connection_enabled.mysql_flexible_server_ssl_connection_enabled.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_ssl_connection_enabled.mysql_flexible_server_ssl_connection_enabled import (
                mysql_flexible_server_ssl_connection_enabled,
            )

            check = mysql_flexible_server_ssl_connection_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == server_name
            assert (
                result[0].resource_id
                == f"/subscriptions/{server_name}/configurations/require_secure_transport"
            )
            assert (
                result[0].status_extended
                == f"SSL connection is enabled for server {server_name} in subscription {AZURE_SUBSCRIPTION}."
            )

    def test_mysql_ssl_connection_disabled(self):
        server_name = str(uuid4())
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {
            AZURE_SUBSCRIPTION: {
                server_name: FlexibleServer(
                    resource_id="/subscriptions/resource_id",
                    location="location",
                    version="version",
                    configurations={
                        "require_secure_transport": Configuration(
                            resource_id=f"/subscriptions/{server_name}/configurations/require_secure_transport",
                            description="description",
                            value="OFF",
                        )
                    },
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_ssl_connection_enabled.mysql_flexible_server_ssl_connection_enabled.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_ssl_connection_enabled.mysql_flexible_server_ssl_connection_enabled import (
                mysql_flexible_server_ssl_connection_enabled,
            )

            check = mysql_flexible_server_ssl_connection_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == server_name
            assert (
                result[0].resource_id
                == f"/subscriptions/{server_name}/configurations/require_secure_transport"
            )
            assert (
                result[0].status_extended
                == f"SSL connection is disabled for server {server_name} in subscription {AZURE_SUBSCRIPTION}."
            )

    def test_mysql_ssl_connection_no_configuration(self):
        server_name = str(uuid4())
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {
            AZURE_SUBSCRIPTION: {
                server_name: FlexibleServer(
                    resource_id="/subscriptions/resource_id",
                    location="location",
                    version="version",
                    configurations={},
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_ssl_connection_enabled.mysql_flexible_server_ssl_connection_enabled.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_ssl_connection_enabled.mysql_flexible_server_ssl_connection_enabled import (
                mysql_flexible_server_ssl_connection_enabled,
            )

            check = mysql_flexible_server_ssl_connection_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == server_name
            assert result[0].resource_id == server_name
            assert (
                result[0].status_extended
                == f"SSL connection is disabled for server {server_name} in subscription {AZURE_SUBSCRIPTION}."
            )

    def test_mysql_ssl_connection_enabled_and_disabled(self):
        server_name_1 = str(uuid4())
        server_name_2 = str(uuid4())
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {
            AZURE_SUBSCRIPTION: {
                server_name_1: FlexibleServer(
                    resource_id="/subscriptions/resource_id",
                    location="location",
                    version="version",
                    configurations={
                        "require_secure_transport": Configuration(
                            resource_id=f"/subscriptions/{server_name_1}/configurations/require_secure_transport",
                            description="description",
                            value="ON",
                        )
                    },
                ),
                server_name_2: FlexibleServer(
                    resource_id="/subscriptions/resource_id",
                    location="location",
                    version="version",
                    configurations={
                        "require_secure_transport": Configuration(
                            resource_id=f"/subscriptions/{server_name_2}/configurations/require_secure_transport",
                            description="description",
                            value="OFF",
                        )
                    },
                ),
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_ssl_connection_enabled.mysql_flexible_server_ssl_connection_enabled.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_ssl_connection_enabled.mysql_flexible_server_ssl_connection_enabled import (
                mysql_flexible_server_ssl_connection_enabled,
            )

            check = mysql_flexible_server_ssl_connection_enabled()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == server_name_1
            assert (
                result[0].resource_id
                == f"/subscriptions/{server_name_1}/configurations/require_secure_transport"
            )
            assert (
                result[0].status_extended
                == f"SSL connection is enabled for server {server_name_1} in subscription {AZURE_SUBSCRIPTION}."
            )
            assert result[1].status == "FAIL"
            assert result[1].subscription == AZURE_SUBSCRIPTION
            assert result[1].resource_name == server_name_2
            assert (
                result[1].resource_id
                == f"/subscriptions/{server_name_2}/configurations/require_secure_transport"
            )
            assert (
                result[1].status_extended
                == f"SSL connection is disabled for server {server_name_2} in subscription {AZURE_SUBSCRIPTION}."
            )
