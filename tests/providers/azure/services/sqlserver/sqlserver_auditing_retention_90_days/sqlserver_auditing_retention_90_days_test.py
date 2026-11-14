from unittest import mock
from uuid import uuid4

import pytest
from azure.mgmt.sql.models import ServerBlobAuditingPolicy

from prowler.providers.azure.services.sqlserver.sqlserver_service import Server
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)


class Test_sqlserver_auditing_retention_90_days:
    @pytest.mark.parametrize(
        "policies, expected_status, expected_detail",
        [
            ([("Enabled", 0)], "PASS", "has unlimited auditing retention."),
            ([("Enabled", 1)], "FAIL", "has auditing retention less than 91 days."),
            ([("Enabled", 89)], "FAIL", "has auditing retention less than 91 days."),
            ([("Enabled", 90)], "FAIL", "has auditing retention less than 91 days."),
            ([("Enabled", 91)], "PASS", "has auditing retention greater than 90 days."),
            (
                [("Enabled", 365)],
                "PASS",
                "has auditing retention greater than 90 days.",
            ),
            ([("Disabled", 0)], "FAIL", "has auditing disabled."),
            (
                [("Enabled", 0), ("Enabled", 30)],
                "FAIL",
                "has auditing retention less than 91 days.",
            ),
            (
                [("Enabled", 30), ("Enabled", 0)],
                "FAIL",
                "has auditing retention less than 91 days.",
            ),
            (
                [("Enabled", 0), ("Disabled", 0)],
                "FAIL",
                "has auditing disabled.",
            ),
            (
                [("Disabled", 0), ("Enabled", 0)],
                "FAIL",
                "has auditing disabled.",
            ),
            (
                [("Enabled", 0), ("Enabled", 91)],
                "PASS",
                "has auditing retention greater than 90 days.",
            ),
            (
                [("Enabled", 91), ("Enabled", 0)],
                "PASS",
                "has unlimited auditing retention.",
            ),
        ],
    )
    def test_retention_semantics(self, policies, expected_status, expected_detail):
        sql_server_id = str(uuid4())
        sql_server_name = "audit-retention-server"
        server = Server(
            id=sql_server_id,
            name=sql_server_name,
            public_network_access="",
            minimal_tls_version="",
            administrators=None,
            auditing_policies=[
                ServerBlobAuditingPolicy(state=state, retention_days=days)
                for state, days in policies
            ],
            firewall_rules=None,
            databases=None,
            encryption_protector=None,
            location="westeurope",
        )
        sqlserver_client = mock.MagicMock()
        sqlserver_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        sqlserver_client.sql_servers = {AZURE_SUBSCRIPTION_ID: [server]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days.sqlserver_client",
                new=sqlserver_client,
            ),
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days import (
                sqlserver_auditing_retention_90_days,
            )

            result = sqlserver_auditing_retention_90_days().execute()

        assert len(result) == 1
        assert result[0].status == expected_status
        assert result[0].status_extended == (
            f"SQL Server {sql_server_name} from subscription "
            f"{AZURE_SUBSCRIPTION_DISPLAY} {expected_detail}"
        )
        assert result[0].resource_id == sql_server_id
        assert result[0].resource_name == sql_server_name
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID
        assert result[0].location == "westeurope"

    def test_no_sql_servers(self):
        sqlserver_client = mock.MagicMock
        sqlserver_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        sqlserver_client.sql_servers = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days.sqlserver_client",
                new=sqlserver_client,
            ),
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days import (
                sqlserver_auditing_retention_90_days,
            )

            check = sqlserver_auditing_retention_90_days()
            result = check.execute()
            assert len(result) == 0

    def test_sql_servers_auditing_policy_disabled(self):
        sqlserver_client = mock.MagicMock
        sqlserver_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUBSCRIPTION_ID: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=[ServerBlobAuditingPolicy(state="Disabled")],
                    firewall_rules=None,
                    databases=None,
                    encryption_protector=None,
                    location="location",
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days.sqlserver_client",
                new=sqlserver_client,
            ),
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days import (
                sqlserver_auditing_retention_90_days,
            )

            check = sqlserver_auditing_retention_90_days()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} has auditing disabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"

    def test_sql_servers_auditing_retention_less_than_90_days(self):
        sqlserver_client = mock.MagicMock
        sqlserver_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUBSCRIPTION_ID: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=[
                        ServerBlobAuditingPolicy(state="Enabled", retention_days=89)
                    ],
                    firewall_rules=None,
                    databases=None,
                    encryption_protector=None,
                    location="location",
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days.sqlserver_client",
                new=sqlserver_client,
            ),
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days import (
                sqlserver_auditing_retention_90_days,
            )

            check = sqlserver_auditing_retention_90_days()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} has auditing retention less than 91 days."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"

    def test_sql_servers_auditing_retention_greater_than_90_days(self):
        sqlserver_client = mock.MagicMock
        sqlserver_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUBSCRIPTION_ID: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=[
                        ServerBlobAuditingPolicy(state="Enabled", retention_days=91)
                    ],
                    firewall_rules=None,
                    databases=None,
                    encryption_protector=None,
                    location="location",
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days.sqlserver_client",
                new=sqlserver_client,
            ),
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days import (
                sqlserver_auditing_retention_90_days,
            )

            check = sqlserver_auditing_retention_90_days()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} has auditing retention greater than 90 days."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"

    def test_sql_servers_two_auditing_policies_with_auditing_retention_greater_than_90_days(
        self,
    ):
        sqlserver_client = mock.MagicMock
        sqlserver_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUBSCRIPTION_ID: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=[
                        ServerBlobAuditingPolicy(state="Enabled", retention_days=91),
                        ServerBlobAuditingPolicy(state="Enabled", retention_days=100),
                    ],
                    firewall_rules=None,
                    databases=None,
                    encryption_protector=None,
                    location="location",
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days.sqlserver_client",
                new=sqlserver_client,
            ),
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days import (
                sqlserver_auditing_retention_90_days,
            )

            check = sqlserver_auditing_retention_90_days()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} has auditing retention greater than 90 days."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"

    def test_sql_servers_two_auditing_policies_with_one_auditing_retention_less_than_90_days(
        self,
    ):
        sqlserver_client = mock.MagicMock
        sqlserver_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUBSCRIPTION_ID: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=[
                        ServerBlobAuditingPolicy(state="Enabled", retention_days=91),
                        ServerBlobAuditingPolicy(state="Enabled", retention_days=80),
                    ],
                    firewall_rules=None,
                    databases=None,
                    encryption_protector=None,
                    location="location",
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days.sqlserver_client",
                new=sqlserver_client,
            ),
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days import (
                sqlserver_auditing_retention_90_days,
            )

            check = sqlserver_auditing_retention_90_days()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} has auditing retention less than 91 days."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"
