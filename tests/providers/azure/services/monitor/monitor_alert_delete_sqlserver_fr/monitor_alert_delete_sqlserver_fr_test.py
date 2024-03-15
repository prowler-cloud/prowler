from unittest import mock

from azure.mgmt.monitor.models import AlertRuleAnyOfOrLeafCondition

from prowler.providers.azure.services.monitor.monitor_service import (
    AlertRule,
    AlertRuleAllOfCondition,
)
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION


class Test_monitor_alert_delete_sqlserver_fr:
    def test_monitor_alert_delete_sqlserver_fr_no_subscriptions(self):
        monitor_client = mock.MagicMock()
        monitor_client.alert_rules = {}
        with mock.patch(
            "prowler.providers.azure.services.monitor.monitor_alert_delete_sqlserver_fr.monitor_alert_delete_sqlserver_fr.monitor_client",
            new=monitor_client,
        ):
            from prowler.providers.azure.services.monitor.monitor_alert_delete_sqlserver_fr.monitor_alert_delete_sqlserver_fr import (
                monitor_alert_delete_sqlserver_fr,
            )

            check = monitor_alert_delete_sqlserver_fr()
            result = check.execute()
            assert len(result) == 0

    def test_no_alert_rules(self):
        monitor_client = mock.MagicMock()
        monitor_client.alert_rules = {AZURE_SUBSCRIPTION: []}
        with mock.patch(
            "prowler.providers.azure.services.monitor.monitor_alert_delete_sqlserver_fr.monitor_alert_delete_sqlserver_fr.monitor_client",
            new=monitor_client,
        ):
            from prowler.providers.azure.services.monitor.monitor_alert_delete_sqlserver_fr.monitor_alert_delete_sqlserver_fr import (
                monitor_alert_delete_sqlserver_fr,
            )

            check = monitor_alert_delete_sqlserver_fr()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == "Monitor"
            assert result[0].resource_id == "Monitor"
            assert (
                result[0].status_extended
                == f"There is not an alert for deleting SQL Server firewall rule in subscription {AZURE_SUBSCRIPTION}."
            )

    def test_alert_rules_configured(self):
        monitor_client = mock.MagicMock
        monitor_client.alert_rules = {
            AZURE_SUBSCRIPTION: [
                AlertRule(
                    id="id",
                    name="name",
                    condition=AlertRuleAllOfCondition(
                        all_of=[
                            AlertRuleAnyOfOrLeafCondition(),
                            AlertRuleAnyOfOrLeafCondition(
                                equals="Microsoft.Sql/servers/firewallRules/delete",
                                field="operationName",
                            ),
                        ]
                    ),
                    enabled=False,
                    description="description",
                ),
                AlertRule(
                    id="id2",
                    name="name2",
                    condition=AlertRuleAllOfCondition(
                        all_of=[
                            AlertRuleAnyOfOrLeafCondition(),
                            AlertRuleAnyOfOrLeafCondition(
                                equals="Microsoft.Sql/servers/firewallRules/delete",
                                field="operationName",
                            ),
                        ]
                    ),
                    enabled=True,
                    description="description2",
                ),
            ]
        }
        with mock.patch(
            "prowler.providers.azure.services.monitor.monitor_alert_delete_sqlserver_fr.monitor_alert_delete_sqlserver_fr.monitor_client",
            new=monitor_client,
        ):
            from prowler.providers.azure.services.monitor.monitor_alert_delete_sqlserver_fr.monitor_alert_delete_sqlserver_fr import (
                monitor_alert_delete_sqlserver_fr,
            )

            check = monitor_alert_delete_sqlserver_fr()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == "name2"
            assert result[0].resource_id == "id2"
            assert (
                result[0].status_extended
                == f"There is an alert configured for deleting SQL Server firewall rule in subscription {AZURE_SUBSCRIPTION}."
            )
