from unittest import mock

from azure.mgmt.monitor.models import AlertRuleAnyOfOrLeafCondition

from prowler.providers.azure.services.monitor.monitor_service import (
    AlertRuleAllOfCondition,
    AlertRules,
)
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION


class Test_monitor_alert_create_update_nsg:
    def test_monitor_alert_create_update_nsg_no_subscriptions(self):
        monitor_client = mock.MagicMock
        monitor_client.alert_rules = {}
        with mock.patch(
            "prowler.providers.azure.services.monitor.monitor_alert_create_update_nsg.monitor_alert_create_update_nsg.monitor_client",
            new=monitor_client,
        ):
            from prowler.providers.azure.services.monitor.monitor_alert_create_update_nsg.monitor_alert_create_update_nsg import (
                monitor_alert_create_update_nsg,
            )

            check = monitor_alert_create_update_nsg()
            result = check.execute()
            assert len(result) == 0

    def test_no_alert_rules(self):
        monitor_client = mock.MagicMock()
        monitor_client.alert_rules = {AZURE_SUBSCRIPTION: []}
        with mock.patch(
            "prowler.providers.azure.services.monitor.monitor_alert_create_update_nsg.monitor_alert_create_update_nsg.monitor_client",
            new=monitor_client,
        ):
            from prowler.providers.azure.services.monitor.monitor_alert_create_update_nsg.monitor_alert_create_update_nsg import (
                monitor_alert_create_update_nsg,
            )

            check = monitor_alert_create_update_nsg()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == "Monitor"
            assert result[0].resource_id == "Monitor"
            assert (
                result[0].status_extended
                == f"There is not an alert for Create/Update Network Security Group in subscription {AZURE_SUBSCRIPTION}."
            )

    def test_alert_rules_configured(self):
        monitor_client = mock.MagicMock
        monitor_client.alert_rules = {
            AZURE_SUBSCRIPTION: [
                AlertRules(
                    id="id",
                    name="name",
                    condition=AlertRuleAllOfCondition(
                        all_of=[
                            AlertRuleAnyOfOrLeafCondition(),
                            AlertRuleAnyOfOrLeafCondition(
                                equals="Microsoft.Network/networkSecurityGroups/write"
                            ),
                        ]
                    ),
                    enabled=False,
                    description="description",
                ),
                AlertRules(
                    id="id2",
                    name="name2",
                    condition=AlertRuleAllOfCondition(
                        all_of=[
                            AlertRuleAnyOfOrLeafCondition(),
                            AlertRuleAnyOfOrLeafCondition(
                                equals="Microsoft.Network/networkSecurityGroups/write"
                            ),
                        ]
                    ),
                    enabled=True,
                    description="description2",
                ),
            ]
        }
        with mock.patch(
            "prowler.providers.azure.services.monitor.monitor_alert_create_update_nsg.monitor_alert_create_update_nsg.monitor_client",
            new=monitor_client,
        ):
            from prowler.providers.azure.services.monitor.monitor_alert_create_update_nsg.monitor_alert_create_update_nsg import (
                monitor_alert_create_update_nsg,
            )

            check = monitor_alert_create_update_nsg()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == "name2"
            assert result[0].resource_id == "id2"
            assert (
                result[0].status_extended
                == f"Alert name2 is configured to trigger when a network security group is created or updated in subscription {AZURE_SUBSCRIPTION}."
            )
