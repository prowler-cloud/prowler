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


class Test_mysql_flexible_server_audit_log_enabled:
    def test_mysql_no_subscriptions(self):
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_audit_log_enabled.mysql_flexible_server_audit_log_enabled.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_audit_log_enabled.mysql_flexible_server_audit_log_enabled import (
                mysql_flexible_server_audit_log_enabled,
            )

            check = mysql_flexible_server_audit_log_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_mysql_no_servers(self):
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {AZURE_SUBSCRIPTION: {}}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_audit_log_enabled.mysql_flexible_server_audit_log_enabled.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_audit_log_enabled.mysql_flexible_server_audit_log_enabled import (
                mysql_flexible_server_audit_log_enabled,
            )

            check = mysql_flexible_server_audit_log_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_mysql_audit_log_disabled(self):
        server_name = str(uuid4())
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {
            AZURE_SUBSCRIPTION: {
                server_name: FlexibleServer(
                    resource_id="/subscriptions/resource_id",
                    location="location",
                    version="version",
                    configurations={
                        "audit_log_enabled": Configuration(
                            resource_id=f"/subscriptions/{server_name}/configurations/audit_log_enabled",
                            description="description",
                            value="OFF",
                        )
                    },
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_audit_log_enabled.mysql_flexible_server_audit_log_enabled.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_audit_log_enabled.mysql_flexible_server_audit_log_enabled import (
                mysql_flexible_server_audit_log_enabled,
            )

            check = mysql_flexible_server_audit_log_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == server_name
            assert (
                result[0].resource_id
                == f"/subscriptions/{server_name}/configurations/audit_log_enabled"
            )
            assert (
                result[0].status_extended
                == f"Audit log is disabled for server {server_name} in subscription {AZURE_SUBSCRIPTION}."
            )

    def test_mysql_audit_log_enabled(self):
        server_name = str(uuid4())
        mysql_client = mock.MagicMock
        mysql_client.flexible_servers = {
            AZURE_SUBSCRIPTION: {
                server_name: FlexibleServer(
                    resource_id="/subscriptions/resource_id",
                    location="location",
                    version="version",
                    configurations={
                        "audit_log_enabled": Configuration(
                            resource_id=f"/subscriptions/{server_name}/configurations/audit_log_enabled",
                            description="description",
                            value="ON",
                        )
                    },
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.mysql.mysql_flexible_server_audit_log_enabled.mysql_flexible_server_audit_log_enabled.mysql_client",
            new=mysql_client,
        ):
            from prowler.providers.azure.services.mysql.mysql_flexible_server_audit_log_enabled.mysql_flexible_server_audit_log_enabled import (
                mysql_flexible_server_audit_log_enabled,
            )

            check = mysql_flexible_server_audit_log_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == server_name
            assert (
                result[0].resource_id
                == f"/subscriptions/{server_name}/configurations/audit_log_enabled"
            )
            assert (
                result[0].status_extended
                == f"Audit log is enabled for server {server_name} in subscription {AZURE_SUBSCRIPTION}."
            )
