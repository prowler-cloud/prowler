from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
from azure.mgmt.security.v2024_01_01.models import PricingList

from prowler.providers.azure.services.defender.defender_service import Defender
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)


@pytest.mark.parametrize("pricing_tier", ["Free", "Standard"])
@pytest.mark.parametrize(
    "trial_properties,expected_trial",
    [
        pytest.param({}, None, id="omitted"),
        pytest.param({"freeTrialRemainingTime": None}, None, id="null"),
        pytest.param({"freeTrialRemainingTime": "PT0S"}, timedelta(0), id="expired"),
        pytest.param({"freeTrialRemainingTime": "P1D"}, timedelta(days=1), id="active"),
    ],
)
def test_pricing_inventory_preserves_optional_trial_metadata(
    pricing_tier, trial_properties, expected_trial
):
    """Missing trial metadata must not discard a plan or stop later plans."""
    payload = {"value": []}
    for name in ("AppServices", "CloudPosture", "StorageAccounts"):
        properties = {"pricingTier": "Standard", "freeTrialRemainingTime": "PT0S"}
        if name == "CloudPosture":
            properties = {"pricingTier": pricing_tier, **trial_properties}
        payload["value"].append(
            {
                "id": f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/providers/Microsoft.Security/pricings/{name}",
                "name": name,
                "type": "Microsoft.Security/pricings",
                "properties": properties,
            }
        )

    client = MagicMock()
    client.pricings.list.return_value = PricingList.deserialize(payload)
    defender = Defender.__new__(Defender)
    defender.clients = {AZURE_SUBSCRIPTION_ID: client}
    defender.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
    defender.pricings = defender._get_pricings()

    plans = defender.pricings[AZURE_SUBSCRIPTION_ID]
    assert set(plans) == {"AppServices", "CloudPosture", "StorageAccounts"}
    assert plans["CloudPosture"].free_trial_remaining_time == expected_trial
    assert plans["CloudPosture"].pricing_tier == pricing_tier
    assert plans["StorageAccounts"].free_trial_remaining_time == timedelta(0)
    client.pricings.list.assert_called_once_with(
        scope_id=f"subscriptions/{AZURE_SUBSCRIPTION_ID}"
    )

    with (
        patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ),
        patch(
            "prowler.providers.azure.services.defender.defender_service.Defender",
            return_value=defender,
        ),
        patch(
            "prowler.providers.azure.services.defender.defender_client.defender_client",
            new=defender,
        ),
    ):
        from prowler.providers.azure.services.defender.defender_ensure_defender_cspm_is_on import (
            defender_ensure_defender_cspm_is_on as cspm_module,
        )

        with patch.object(cspm_module, "defender_client", defender):
            findings = cspm_module.defender_ensure_defender_cspm_is_on().execute()

    assert len(findings) == 1
    assert findings[0].status == ("PASS" if pricing_tier == "Standard" else "FAIL")
    assert findings[0].resource_id == plans["CloudPosture"].resource_id
    assert findings[0].subscription == AZURE_SUBSCRIPTION_ID
