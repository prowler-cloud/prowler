from unittest import mock
from unittest.mock import patch

from azure.mgmt.monitor.models import AlertRuleAnyOfOrLeafCondition

from prowler.providers.azure.services.monitor.lib.monitor_alerts import check_alert_rule
from prowler.providers.azure.services.monitor.monitor_service import (
    AlertRule,
    AlertRuleAllOfCondition,
    DiagnosticSetting,
    Monitor,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


def mock_monitor_get_diagnostics_settings(_):
    return {
        AZURE_SUBSCRIPTION_ID: [
            DiagnosticSetting(
                id="id",
                logs=[
                    mock.MagicMock(category="Administrative", enabled=True),
                    mock.MagicMock(category="Security", enabled=True),
                    mock.MagicMock(category="ServiceHealth", enabled=False),
                    mock.MagicMock(category="Alert", enabled=True),
                    mock.MagicMock(category="Recommendation", enabled=False),
                    mock.MagicMock(category="Policy", enabled=True),
                    mock.MagicMock(category="Autoscale", enabled=False),
                    mock.MagicMock(category="ResourceHealth", enabled=False),
                ],
                storage_account_id="/subscriptions/1234a5-123a-123a-123a-1234567890ab/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/storageaccountname",
                storage_account_name="storageaccountname",
                name="name",
            )
        ]
    }


@patch(
    "prowler.providers.azure.services.monitor.monitor_service.Monitor._get_diagnostics_settings",
    new=mock_monitor_get_diagnostics_settings,
)
class Test_Monitor_Service:
    def test_get_client(self):
        monitor = Monitor(set_mocked_azure_provider())
        assert (
            monitor.clients[AZURE_SUBSCRIPTION_ID].__class__.__name__
            == "MonitorManagementClient"
        )

    def test__get_subscriptions__(self):
        monitor = Monitor(set_mocked_azure_provider())
        assert monitor.subscriptions.__class__.__name__ == "dict"

    def test__get_diagnostics_settings(self):
        monitor = Monitor(set_mocked_azure_provider())
        assert len(monitor.diagnostics_settings) == 1
        assert monitor.diagnostics_settings[AZURE_SUBSCRIPTION_ID][0].id == "id"
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION_ID][0].logs[0].enabled
            is True
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION_ID][0].logs[0].category
            == "Administrative"
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION_ID][0].logs[1].enabled
            is True
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION_ID][0].logs[1].category
            == "Security"
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION_ID][0].logs[2].category
            == "ServiceHealth"
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION_ID][0].logs[3].enabled
            is True
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION_ID][0].logs[3].category
            == "Alert"
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION_ID][0].logs[4].category
            == "Recommendation"
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION_ID][0].logs[5].enabled
            is True
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION_ID][0].logs[5].category
            == "Policy"
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION_ID][0].logs[6].category
            == "Autoscale"
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION_ID][0].logs[7].category
            == "ResourceHealth"
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION_ID][0].storage_account_id
            == "/subscriptions/1234a5-123a-123a-123a-1234567890ab/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/storageaccountname"
        )

    def test__monitor_alerts_false__(self):
        alert_rule = AlertRule(
            id="id",
            name="name",
            condition=AlertRuleAllOfCondition(
                all_of=[
                    AlertRuleAnyOfOrLeafCondition(),
                    AlertRuleAnyOfOrLeafCondition(
                        equals="Microsoft.Authorization/policyAssignments/write",
                        field="operationName",
                    ),
                ]
            ),
            enabled=False,
            description="description",
        )

        assert not check_alert_rule(
            alert_rule, "Microsoft.Authorization/policyAssignments/write"
        )

    def test__monitor_alerts_true__(self):
        alert_rule = AlertRule(
            id="id",
            name="name",
            condition=AlertRuleAllOfCondition(
                all_of=[
                    AlertRuleAnyOfOrLeafCondition(),
                    AlertRuleAnyOfOrLeafCondition(
                        equals="Microsoft.Authorization/policyAssignments/write",
                        field="operationName",
                    ),
                ]
            ),
            enabled=True,
            description="description",
        )

        assert check_alert_rule(
            alert_rule, "Microsoft.Authorization/policyAssignments/write"
        )

    def test__monitor_alerts_false_equal__(self):
        alert_rule = AlertRule(
            id="id",
            name="name",
            condition=AlertRuleAllOfCondition(
                all_of=[
                    AlertRuleAnyOfOrLeafCondition(),
                    AlertRuleAnyOfOrLeafCondition(
                        equals="Microsoft.Authorization/policyAssingments/write",
                        field="operationName",
                    ),
                ]
            ),
            enabled=True,
            description="description",
        )

        assert not check_alert_rule(
            alert_rule, "Microsoft.Authorization/policyAssignments/write"
        )
