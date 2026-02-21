from unittest import mock

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_monitor_alert_service_health_exists:
    def test_monitor_alert_service_health_exists_no_subscriptions(self):
        monitor_client = mock.MagicMock()
        monitor_client.alert_rules = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.monitor.monitor_alert_service_health_exists.monitor_alert_service_health_exists.monitor_client",
                new=monitor_client,
            ),
        ):
            from prowler.providers.azure.services.monitor.monitor_alert_service_health_exists.monitor_alert_service_health_exists import (
                monitor_alert_service_health_exists,
            )

            check = monitor_alert_service_health_exists()
            result = check.execute()
            assert len(result) == 0

    def test_no_alert_rules(self):
        monitor_client = mock.MagicMock()
        monitor_client.alert_rules = {AZURE_SUBSCRIPTION_ID: []}
        monitor_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_ID}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.monitor.monitor_alert_service_health_exists.monitor_alert_service_health_exists.monitor_client",
                new=monitor_client,
            ),
        ):
            from prowler.providers.azure.services.monitor.monitor_alert_service_health_exists.monitor_alert_service_health_exists import (
                monitor_alert_service_health_exists,
            )

            check = monitor_alert_service_health_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_id == f"/subscriptions/{AZURE_SUBSCRIPTION_ID}"
            assert (
                result[0].status_extended
                == f"There is no activity log alert for Service Health in subscription {AZURE_SUBSCRIPTION_ID}."
            )

    def test_alert_rules_configured(self):
        monitor_client = mock.MagicMock()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.monitor.monitor_alert_service_health_exists.monitor_alert_service_health_exists.monitor_client",
                new=monitor_client,
            ),
        ):
            from prowler.providers.azure.services.monitor.monitor_alert_service_health_exists.monitor_alert_service_health_exists import (
                monitor_alert_service_health_exists,
            )
            from prowler.providers.azure.services.monitor.monitor_service import (
                AlertRule,
                AlertRuleAllOfCondition,
                AlertRuleAnyOfOrLeafCondition,
            )

            monitor_client.alert_rules = {
                AZURE_SUBSCRIPTION_ID: [
                    AlertRule(
                        id="id1",
                        name="name1",
                        condition=AlertRuleAllOfCondition(
                            all_of=[
                                AlertRuleAnyOfOrLeafCondition(
                                    field="category", equals="ServiceHealth"
                                ),
                                AlertRuleAnyOfOrLeafCondition(
                                    field="properties.incidentType", equals="Incident"
                                ),
                            ]
                        ),
                        enabled=True,
                        description="desc1",
                    ),
                ]
            }
            check = monitor_alert_service_health_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "name1"
            assert result[0].resource_id == "id1"
            assert (
                result[0].status_extended
                == f"There is an activity log alert for Service Health in subscription {AZURE_SUBSCRIPTION_ID}."
            )

    def test_alert_rules_configured_but_disabled(self):
        monitor_client = mock.MagicMock()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.monitor.monitor_alert_service_health_exists.monitor_alert_service_health_exists.monitor_client",
                new=monitor_client,
            ),
        ):
            from prowler.providers.azure.services.monitor.monitor_alert_service_health_exists.monitor_alert_service_health_exists import (
                monitor_alert_service_health_exists,
            )
            from prowler.providers.azure.services.monitor.monitor_service import (
                AlertRule,
                AlertRuleAllOfCondition,
                AlertRuleAnyOfOrLeafCondition,
            )

            monitor_client.alert_rules = {
                AZURE_SUBSCRIPTION_ID: [
                    AlertRule(
                        id="id1",
                        name="name1",
                        condition=AlertRuleAllOfCondition(
                            all_of=[
                                AlertRuleAnyOfOrLeafCondition(
                                    field="category", equals="ServiceHealth"
                                ),
                                AlertRuleAnyOfOrLeafCondition(
                                    field="properties.incidentType", equals="Incident"
                                ),
                            ]
                        ),
                        enabled=False,
                        description="desc1",
                    ),
                ]
            }
            monitor_client.subscriptions = {
                AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_ID
            }
            check = monitor_alert_service_health_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_id == f"/subscriptions/{AZURE_SUBSCRIPTION_ID}"
            assert (
                result[0].status_extended
                == f"There is no activity log alert for Service Health in subscription {AZURE_SUBSCRIPTION_ID}."
            )
