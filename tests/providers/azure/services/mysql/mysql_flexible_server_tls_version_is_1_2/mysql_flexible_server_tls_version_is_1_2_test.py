from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.mysql.mysql_service import (
    Configuration,
    FlexibleServer,
)
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION


class Test_mysql_flexible_server_tls_version_is_1_2:
    def test_mysql_no_subscriptions(self):
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {}

        with mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_tls_version_is_1_2.mysql_flexible_server_tls_version_is_1_2.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_tls_version_is_1_2.mysql_flexible_server_tls_version_is_1_2 import (
                mysql_flexible_server_tls_version_is_1_2,
            )

            check = mysql_flexible_server_tls_version_is_1_2()
            result = check.execute()
            assert len(result) == 0

    def test_mysql_no_servers(self):
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {AZURE_SUBSCRIPTION: {}}

        with mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_tls_version_is_1_2.mysql_flexible_server_tls_version_is_1_2.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_tls_version_is_1_2.mysql_flexible_server_tls_version_is_1_2 import (
                mysql_flexible_server_tls_version_is_1_2,
            )

            check = mysql_flexible_server_tls_version_is_1_2()
            result = check.execute()
            assert len(result) == 0

    def test_mysql_flexible_server_tls_version_is_1_2(self):
        server_name = str(uuid4())
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {
            AZURE_SUBSCRIPTION: {
                server_name: FlexibleServer(
                    resource_id="/subscriptions/resource_id",
                    location="location",
                    version="version",
                    configurations={
                        "tls_version": Configuration(
                            resource_id=f"/subscriptions/{server_name}/configurations/tls_version",
                            description="description",
                            value="TLSv1.2",
                        )
                    },
                )
            }
        }
        with mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_tls_version_is_1_2.mysql_flexible_server_tls_version_is_1_2.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_tls_version_is_1_2.mysql_flexible_server_tls_version_is_1_2 import (
                mysql_flexible_server_tls_version_is_1_2,
            )

            check = mysql_flexible_server_tls_version_is_1_2()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == server_name
            assert (
                result[0].resource_id
                == f"/subscriptions/{server_name}/configurations/tls_version"
            )
            assert (
                result[0].status_extended
                == f"TLS version is TLSv1.2 in server {server_name} in subscription {AZURE_SUBSCRIPTION}. This version of TLS is considered secure."
            )

    def test_mysql_tls_version_is_1_3(self):
        server_name = str(uuid4())
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {
            AZURE_SUBSCRIPTION: {
                server_name: FlexibleServer(
                    resource_id="/subscriptions/resource_id",
                    location="location",
                    version="version",
                    configurations={
                        "tls_version": Configuration(
                            resource_id=f"/subscriptions/{server_name}/configurations/tls_version",
                            description="description",
                            value="TLSv1.3",
                        )
                    },
                )
            }
        }
        with mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_tls_version_is_1_2.mysql_flexible_server_tls_version_is_1_2.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_tls_version_is_1_2.mysql_flexible_server_tls_version_is_1_2 import (
                mysql_flexible_server_tls_version_is_1_2,
            )

            check = mysql_flexible_server_tls_version_is_1_2()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == server_name
            assert (
                result[0].resource_id
                == f"/subscriptions/{server_name}/configurations/tls_version"
            )
            assert (
                result[0].status_extended
                == f"TLS version is TLSv1.3 in server {server_name} in subscription {AZURE_SUBSCRIPTION}. This version of TLS is considered secure."
            )

    def test_mysql_tls_version_is_not_1_2(self):
        server_name = str(uuid4())
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {
            AZURE_SUBSCRIPTION: {
                server_name: FlexibleServer(
                    resource_id="/subscriptions/resource_id",
                    location="location",
                    version="version",
                    configurations={
                        "tls_version": Configuration(
                            resource_id=f"/subscriptions/{server_name}/configurations/tls_version",
                            description="description",
                            value="TLSv1.1",
                        )
                    },
                )
            }
        }
        with mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_tls_version_is_1_2.mysql_flexible_server_tls_version_is_1_2.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_tls_version_is_1_2.mysql_flexible_server_tls_version_is_1_2 import (
                mysql_flexible_server_tls_version_is_1_2,
            )

            check = mysql_flexible_server_tls_version_is_1_2()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == server_name
            assert (
                result[0].resource_id
                == f"/subscriptions/{server_name}/configurations/tls_version"
            )
            assert (
                result[0].status_extended
                == f"TLS version is TLSv1.1 in server {server_name} in subscription {AZURE_SUBSCRIPTION}. This version of TLS is considered insecure."
            )

    def test_mysql_tls_version_is_1_1_and_1_3(self):
        server_name = str(uuid4())
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {
            AZURE_SUBSCRIPTION: {
                server_name: FlexibleServer(
                    resource_id="/subscriptions/resource_id",
                    location="location",
                    version="version",
                    configurations={
                        "tls_version": Configuration(
                            resource_id=f"/subscriptions/{server_name}/configurations/tls_version",
                            description="description",
                            value="TLSv1.1,TLSv1.3",
                        )
                    },
                )
            }
        }
        with mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_tls_version_is_1_2.mysql_flexible_server_tls_version_is_1_2.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_tls_version_is_1_2.mysql_flexible_server_tls_version_is_1_2 import (
                mysql_flexible_server_tls_version_is_1_2,
            )

            check = mysql_flexible_server_tls_version_is_1_2()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == server_name
            assert (
                result[0].resource_id
                == f"/subscriptions/{server_name}/configurations/tls_version"
            )
            assert (
                result[0].status_extended
                == f"TLS version is TLSv1.1,TLSv1.3 in server {server_name} in subscription {AZURE_SUBSCRIPTION}. This version of TLS is considered secure."
            )
