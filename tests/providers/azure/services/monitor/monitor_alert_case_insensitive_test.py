import importlib
from unittest import mock

import pytest
from azure.mgmt.monitor.models import AlertRuleAnyOfOrLeafCondition

from prowler.providers.azure.services.monitor.lib.monitor_alerts import check_alert_rule
from prowler.providers.azure.services.monitor.monitor_service import (
    AlertRule,
    AlertRuleAllOfCondition,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)


@pytest.mark.parametrize(
    "field, value, enabled, expected",
    [
        ("operationName", "Microsoft.Network/networkSecurityGroups/write", True, True),
        ("OPERATIONNAME", "microsoft.network/networksecuritygroups/WRITE", True, True),
        ("operationname", "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE", True, True),
        (
            "OPERATIONNAME",
            "microsoft.network/networksecuritygroups/WRITE",
            False,
            False,
        ),
        ("resourceType", "Microsoft.Network/networkSecurityGroups/write", True, False),
        (
            "operationName",
            "Microsoft.Network/networkSecurityGroups/delete",
            True,
            False,
        ),
        (None, "Microsoft.Network/networkSecurityGroups/write", True, False),
        ("operationName", None, True, False),
    ],
)
def test_operation_condition_is_case_insensitive(field, value, enabled, expected):
    rule = AlertRule(
        id="alert-id",
        name="alert-name",
        condition=AlertRuleAllOfCondition(
            all_of=[
                AlertRuleAnyOfOrLeafCondition.from_dict(
                    {
                        "field": field,
                        "equals": value,
                    }
                )
            ]
        ),
        enabled=enabled,
        description=None,
    )

    assert (
        check_alert_rule(rule, "Microsoft.Network/networkSecurityGroups/write")
        is expected
    )


@pytest.mark.parametrize(
    "category_field, category, incident_field, incident, enabled, expected_status",
    [
        (
            "category",
            "ServiceHealth",
            "properties.incidentType",
            "Incident",
            True,
            "PASS",
        ),
        (
            "CATEGORY",
            "servicehealth",
            "PROPERTIES.INCIDENTTYPE",
            "INCIDENT",
            True,
            "PASS",
        ),
        (
            "Category",
            "SERVICEHEALTH",
            "properties.incidenttype",
            "incident",
            True,
            "PASS",
        ),
        (
            "CATEGORY",
            "servicehealth",
            "PROPERTIES.INCIDENTTYPE",
            "INCIDENT",
            False,
            "FAIL",
        ),
        (
            "category",
            "Administrative",
            "properties.incidentType",
            "Incident",
            True,
            "FAIL",
        ),
        (
            "category",
            "ServiceHealth",
            "properties.incidentType",
            "Maintenance",
            True,
            "FAIL",
        ),
        (None, "ServiceHealth", "properties.incidentType", "Incident", True, "FAIL"),
        ("category", None, "properties.incidentType", "Incident", True, "FAIL"),
        ("category", "ServiceHealth", None, "Incident", True, "FAIL"),
        ("category", "ServiceHealth", "properties.incidentType", None, True, "FAIL"),
    ],
)
def test_service_health_conditions_are_case_insensitive(
    category_field, category, incident_field, incident, enabled, expected_status
):
    rule = AlertRule(
        id="health-id",
        name="health-name",
        condition=AlertRuleAllOfCondition(
            all_of=[
                AlertRuleAnyOfOrLeafCondition(),
                AlertRuleAnyOfOrLeafCondition.from_dict(
                    {"field": category_field, "equals": category}
                ),
                AlertRuleAnyOfOrLeafCondition.from_dict(
                    {"field": incident_field, "equals": incident}
                ),
            ]
        ),
        enabled=enabled,
        description=None,
    )
    client = mock.MagicMock()
    client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
    client.alert_rules = {AZURE_SUBSCRIPTION_ID: [rule]}
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ),
        mock.patch(
            "prowler.providers.azure.services.monitor.monitor_alert_service_health_exists.monitor_alert_service_health_exists.monitor_client",
            new=client,
        ),
    ):
        from prowler.providers.azure.services.monitor.monitor_alert_service_health_exists.monitor_alert_service_health_exists import (
            monitor_alert_service_health_exists,
        )

        result = monitor_alert_service_health_exists().execute()

    assert len(result) == 1
    assert result[0].status == expected_status
    if expected_status == "PASS":
        assert result[0].resource_id == "health-id"
        assert result[0].resource_name == "health-name"
    else:
        assert result[0].resource_id == f"/subscriptions/{AZURE_SUBSCRIPTION_ID}"
        assert result[0].resource_name == AZURE_SUBSCRIPTION_ID
    assert result[0].subscription == AZURE_SUBSCRIPTION_ID


@pytest.mark.parametrize(
    "check_name, operation",
    [
        (
            "monitor_alert_create_policy_assignment",
            "Microsoft.Authorization/policyAssignments/write",
        ),
        (
            "monitor_alert_delete_policy_assignment",
            "Microsoft.Authorization/policyAssignments/delete",
        ),
        (
            "monitor_alert_create_update_nsg",
            "Microsoft.Network/networkSecurityGroups/write",
        ),
        ("monitor_alert_delete_nsg", "Microsoft.Network/networkSecurityGroups/delete"),
        (
            "monitor_alert_delete_nsg",
            "Microsoft.ClassicNetwork/networkSecurityGroups/delete",
        ),
        (
            "monitor_alert_create_update_security_solution",
            "Microsoft.Security/securitySolutions/write",
        ),
        (
            "monitor_alert_delete_security_solution",
            "Microsoft.Security/securitySolutions/delete",
        ),
        (
            "monitor_alert_create_update_public_ip_address_rule",
            "Microsoft.Network/publicIPAddresses/write",
        ),
        (
            "monitor_alert_delete_public_ip_address_rule",
            "Microsoft.Network/publicIPAddresses/delete",
        ),
        (
            "monitor_alert_create_update_sqlserver_fr",
            "Microsoft.Sql/servers/firewallRules/write",
        ),
        (
            "monitor_alert_delete_sqlserver_fr",
            "Microsoft.Sql/servers/firewallRules/delete",
        ),
    ],
)
@pytest.mark.parametrize(
    "field, enabled, expected_status",
    [
        ("OPERATIONNAME", True, "PASS"),
        ("operationname", True, "PASS"),
        ("OPERATIONNAME", False, "FAIL"),
        ("resourceType", True, "FAIL"),
    ],
)
def test_operation_checks_preserve_condition_semantics(
    check_name, operation, field, enabled, expected_status
):
    rule = AlertRule(
        id="operation-id",
        name="operation-name",
        condition=AlertRuleAllOfCondition(
            all_of=[
                AlertRuleAnyOfOrLeafCondition(),
                AlertRuleAnyOfOrLeafCondition.from_dict(
                    {"field": field, "equals": operation.swapcase()}
                ),
            ]
        ),
        enabled=enabled,
        description=None,
    )
    client = mock.MagicMock()
    client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
    client.alert_rules = {AZURE_SUBSCRIPTION_ID: [rule]}
    with mock.patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=set_mocked_azure_provider(),
    ):
        module = importlib.import_module(
            f"prowler.providers.azure.services.monitor.{check_name}.{check_name}"
        )
        with mock.patch.object(module, "monitor_client", new=client):
            result = getattr(module, check_name)().execute()

    assert len(result) == 1
    assert result[0].status == expected_status
    assert result[0].subscription == AZURE_SUBSCRIPTION_ID
    if expected_status == "PASS":
        assert result[0].resource_id == "operation-id"
        assert result[0].resource_name == "operation-name"
    else:
        assert result[0].resource_id == f"/subscriptions/{AZURE_SUBSCRIPTION_ID}"
        assert result[0].resource_name == AZURE_SUBSCRIPTION_ID
