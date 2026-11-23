from importlib import import_module
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest
from azure.mgmt.sql.models import ServerVulnerabilityAssessment

from prowler.providers.azure.services.sqlserver.sqlserver_service import SQLServer
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    RESOURCE_GROUP,
    set_mocked_azure_provider,
)


class Test_SQLServer_Optional_Recurring_Scans:
    @pytest.mark.parametrize("scoped", [False, True])
    @pytest.mark.parametrize(
        "configuration", ["omitted", "null", "disabled", "enabled"]
    )
    def test_optional_recurring_scans_preserves_inventory(self, scoped, configuration):
        """Absent recurring-scan settings must not hide either SQL server."""
        service = object.__new__(SQLServer)
        client = MagicMock()
        servers = [
            SimpleNamespace(
                id=f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Sql/servers/sql-{index}",
                name=f"sql-{index}",
                public_network_access="Disabled",
                minimal_tls_version="1.2",
            )
            for index in range(2)
        ]
        assessments = []
        for index, server in enumerate(servers):
            properties = {
                "storageContainerPath": "https://example.blob.core.windows.net/scans/"
            }
            state = configuration if index == 0 else "enabled"
            if state == "null":
                properties["recurringScans"] = None
            elif state != "omitted":
                properties["recurringScans"] = {
                    "isEnabled": state == "enabled",
                    "emailSubscriptionAdmins": state == "enabled",
                    "emails": ["security@example.com"] if state == "enabled" else [],
                }
            assessments.append(
                ServerVulnerabilityAssessment.deserialize(
                    {
                        "id": f"{server.id}/vulnerabilityAssessments/default",
                        "name": "default",
                        "type": "Microsoft.Sql/servers/vulnerabilityAssessments",
                        "properties": properties,
                    }
                )
            )
        client.servers.list.return_value = servers
        client.servers.list_by_resource_group.return_value = servers
        client.server_vulnerability_assessments.get.side_effect = assessments
        service.clients = {AZURE_SUBSCRIPTION_ID: client}
        service.resource_groups = (
            {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]} if scoped else None
        )
        service.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}

        with (
            patch.object(
                SQLServer, "_get_server_blob_auditing_policies", return_value=[]
            ),
            patch.object(SQLServer, "_get_firewall_rules", return_value=[]),
            patch.object(SQLServer, "_get_enctyption_protectors", return_value=None),
            patch.object(
                SQLServer, "_get_server_security_alert_policies", return_value=None
            ),
            patch.object(SQLServer, "_get_location", return_value="westeurope"),
            patch.object(SQLServer, "_get_databases", return_value=[]),
        ):
            service.sql_servers = service._get_sql_servers()

        inventory = service.sql_servers[AZURE_SUBSCRIPTION_ID]
        assert [server.id for server in inventory] == [server.id for server in servers]
        assert client.server_vulnerability_assessments.get.call_args_list == [
            call(
                resource_group_name=RESOURCE_GROUP,
                server_name=server.name,
                vulnerability_assessment_name="default",
            )
            for server in servers
        ]
        first_assessment = inventory[0].vulnerability_assessment
        assert first_assessment.id == assessments[0].id
        assert (
            first_assessment.storage_container_path
            == assessments[0].storage_container_path
        )
        if configuration in ("omitted", "null"):
            assert first_assessment.recurring_scans is None
        else:
            assert first_assessment.recurring_scans.is_enabled is (
                configuration == "enabled"
            )

        expected_status = "PASS" if configuration == "enabled" else "FAIL"
        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            patch(
                "prowler.providers.azure.services.sqlserver.sqlserver_service.SQLServer",
                return_value=service,
            ),
        ):
            for check_name in (
                "sqlserver_va_periodic_recurring_scans_enabled",
                "sqlserver_va_emails_notifications_admins_enabled",
                "sqlserver_va_scan_reports_configured",
            ):
                module_path = f"prowler.providers.azure.services.sqlserver.{check_name}.{check_name}"
                with patch(f"{module_path}.sqlserver_client", new=service):
                    check = getattr(import_module(module_path), check_name)()
                    findings = check.execute()
                assert [finding.status for finding in findings] == [
                    expected_status,
                    "PASS",
                ]
                assert [finding.resource_id for finding in findings] == [
                    server.id for server in servers
                ]
