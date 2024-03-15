from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.mysql.mysql_service import (
    Configuration,
    FlexibleServer,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_provider,
)


class Test_mysql_flexible_server_minimum_tls_version_12:
    def test_mysql_no_subscriptions(self):
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_minimum_tls_version_12.mysql_flexible_server_minimum_tls_version_12.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_minimum_tls_version_12.mysql_flexible_server_minimum_tls_version_12 import (
                mysql_flexible_server_minimum_tls_version_12,
            )

            check = mysql_flexible_server_minimum_tls_version_12()
            result = check.execute()
            assert len(result) == 0

    def test_mysql_no_servers(self):
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {AZURE_SUBSCRIPTION: {}}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_minimum_tls_version_12.mysql_flexible_server_minimum_tls_version_12.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_minimum_tls_version_12.mysql_flexible_server_minimum_tls_version_12 import (
                mysql_flexible_server_minimum_tls_version_12,
            )

            check = mysql_flexible_server_minimum_tls_version_12()
            result = check.execute()
            assert len(result) == 0

    def test_mysql_no_tls_configuration(self):
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
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_minimum_tls_version_12.mysql_flexible_server_minimum_tls_version_12.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_minimum_tls_version_12.mysql_flexible_server_minimum_tls_version_12 import (
                mysql_flexible_server_minimum_tls_version_12,
            )

            check = mysql_flexible_server_minimum_tls_version_12()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == server_name
            assert result[0].resource_id == server_name
            assert (
                result[0].status_extended
                == f"TLS version is not configured in server {server_name} in subscription {AZURE_SUBSCRIPTION}."
            )

    def test_mysql_flexible_server_minimum_tls_version_12(self):
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
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_minimum_tls_version_12.mysql_flexible_server_minimum_tls_version_12.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_minimum_tls_version_12.mysql_flexible_server_minimum_tls_version_12 import (
                mysql_flexible_server_minimum_tls_version_12,
            )

            check = mysql_flexible_server_minimum_tls_version_12()
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
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_minimum_tls_version_12.mysql_flexible_server_minimum_tls_version_12.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_minimum_tls_version_12.mysql_flexible_server_minimum_tls_version_12 import (
                mysql_flexible_server_minimum_tls_version_12,
            )

            check = mysql_flexible_server_minimum_tls_version_12()
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
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_minimum_tls_version_12.mysql_flexible_server_minimum_tls_version_12.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_minimum_tls_version_12.mysql_flexible_server_minimum_tls_version_12 import (
                mysql_flexible_server_minimum_tls_version_12,
            )

            check = mysql_flexible_server_minimum_tls_version_12()
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
                == f"TLS version is TLSv1.1 in server {server_name} in subscription {AZURE_SUBSCRIPTION}. There is at leat one version of TLS that is considered insecure."
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
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_minimum_tls_version_12.mysql_flexible_server_minimum_tls_version_12.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_minimum_tls_version_12.mysql_flexible_server_minimum_tls_version_12 import (
                mysql_flexible_server_minimum_tls_version_12,
            )

            check = mysql_flexible_server_minimum_tls_version_12()
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
                == f"TLS version is TLSv1.1,TLSv1.3 in server {server_name} in subscription {AZURE_SUBSCRIPTION}. There is at leat one version of TLS that is considered insecure."
            )
