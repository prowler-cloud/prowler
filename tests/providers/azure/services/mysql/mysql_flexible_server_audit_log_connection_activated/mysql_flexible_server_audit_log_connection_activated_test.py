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


class Test_mysql_flexible_server_audit_log_connection_activated:
    def test_mysql_no_subscriptions(self):
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_audit_log_connection_activated.mysql_flexible_server_audit_log_connection_activated.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_audit_log_connection_activated.mysql_flexible_server_audit_log_connection_activated import (
                mysql_flexible_server_audit_log_connection_activated,
            )

            check = mysql_flexible_server_audit_log_connection_activated()
            result = check.execute()
            assert len(result) == 0

    def test_mysql_no_servers(self):
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {AZURE_SUBSCRIPTION: {}}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_audit_log_connection_activated.mysql_flexible_server_audit_log_connection_activated.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_audit_log_connection_activated.mysql_flexible_server_audit_log_connection_activated import (
                mysql_flexible_server_audit_log_connection_activated,
            )

            check = mysql_flexible_server_audit_log_connection_activated()
            result = check.execute()
            assert len(result) == 0

    def test_mysql_audit_log_connection_not_connection(self):
        server_name = str(uuid4())
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {
            AZURE_SUBSCRIPTION: {
                server_name: FlexibleServer(
                    resource_id="/subscriptions/resource_id",
                    location="location",
                    version="version",
                    configurations={
                        "audit_log_events": Configuration(
                            resource_id=f"/subscriptions/{server_name}/configurations/audit_log_events",
                            description="description",
                            value="ADMIN,DDL",
                        )
                    },
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_audit_log_connection_activated.mysql_flexible_server_audit_log_connection_activated.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_audit_log_connection_activated.mysql_flexible_server_audit_log_connection_activated import (
                mysql_flexible_server_audit_log_connection_activated,
            )

            check = mysql_flexible_server_audit_log_connection_activated()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == server_name
            assert (
                result[0].resource_id
                == f"/subscriptions/{server_name}/configurations/audit_log_events"
            )
            assert (
                result[0].status_extended
                == f"Audit log is disabled for server {server_name} in subscription {AZURE_SUBSCRIPTION}."
            )

    def test_mysql_audit_log_connection_activated(self):
        server_name = str(uuid4())
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {
            AZURE_SUBSCRIPTION: {
                server_name: FlexibleServer(
                    resource_id="/subscriptions/resource_id",
                    location="location",
                    version="version",
                    configurations={
                        "audit_log_events": Configuration(
                            resource_id=f"/subscriptions/{server_name}/configurations/audit_log_events",
                            description="description",
                            value="CONNECTION",
                        )
                    },
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_audit_log_connection_activated.mysql_flexible_server_audit_log_connection_activated.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_audit_log_connection_activated.mysql_flexible_server_audit_log_connection_activated import (
                mysql_flexible_server_audit_log_connection_activated,
            )

            check = mysql_flexible_server_audit_log_connection_activated()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == server_name
            assert (
                result[0].resource_id
                == f"/subscriptions/{server_name}/configurations/audit_log_events"
            )
            assert (
                result[0].status_extended
                == f"Audit log is enabled for server {server_name} in subscription {AZURE_SUBSCRIPTION}."
            )

    def test_mysql_audit_log_connection_activated_with_other_options(self):
        server_name = str(uuid4())
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {
            AZURE_SUBSCRIPTION: {
                server_name: FlexibleServer(
                    resource_id="/subscriptions/resource_id",
                    location="location",
                    version="version",
                    configurations={
                        "audit_log_events": Configuration(
                            resource_id=f"/subscriptions/{server_name}/configurations/audit_log_events",
                            description="description",
                            value="ADMIN,GENERAL,CONNECTION,DDL",
                        )
                    },
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_audit_log_connection_activated.mysql_flexible_server_audit_log_connection_activated.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_audit_log_connection_activated.mysql_flexible_server_audit_log_connection_activated import (
                mysql_flexible_server_audit_log_connection_activated,
            )

            check = mysql_flexible_server_audit_log_connection_activated()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == server_name
            assert (
                result[0].resource_id
                == f"/subscriptions/{server_name}/configurations/audit_log_events"
            )
            assert (
                result[0].status_extended
                == f"Audit log is enabled for server {server_name} in subscription {AZURE_SUBSCRIPTION}."
            )
