from datetime import timedelta
from unittest.mock import patch

from prowler.providers.azure.services.defender.defender_service import (
    Assesment,
    AutoProvisioningSetting,
    Defender,
    Pricing,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUSCRIPTION,
    set_mocked_azure_audit_info,
)


def mock_defender_get_pricings(_):
    return {
        AZURE_SUSCRIPTION: {
            "Standard": Pricing(
                resource_id="resource_id",
                pricing_tier="pricing_tier",
                free_trial_remaining_time=timedelta(days=1),
            )
        }
    }


def mock_defender_get_auto_provisioning_settings(_):
    return {
        AZURE_SUSCRIPTION: {
            "default": AutoProvisioningSetting(
                resource_id="/subscriptions/resource_id",
                resource_name="default",
                resource_type="Microsoft.Security/autoProvisioningSettings",
                auto_provision="On",
            )
        }
    }


def mock_defender_get_assessments(_):
    return {
        AZURE_SUSCRIPTION: {
            "default": Assesment(
                resource_id="/subscriptions/resource_id",
                resource_name="default",
                status="Healthy",
            )
        }
    }


@patch(
    "prowler.providers.azure.services.defender.defender_service.Defender.__get_pricings__",
    new=mock_defender_get_pricings,
)
@patch(
    "prowler.providers.azure.services.defender.defender_service.Defender.__get_auto_provisioning_settings__",
    new=mock_defender_get_auto_provisioning_settings,
)
@patch(
    "prowler.providers.azure.services.defender.defender_service.Defender.__get_assessments__",
    new=mock_defender_get_assessments,
)
class Test_Defender_Service:
    def test__get_client__(self):
        defender = Defender(set_mocked_azure_audit_info())
        assert (
            defender.clients[AZURE_SUSCRIPTION].__class__.__name__ == "SecurityCenter"
        )

    def test__get_subscriptions__(self):
        defender = Defender(set_mocked_azure_audit_info())
        defender = Defender(set_mocked_azure_audit_info())
        assert defender.subscriptions.__class__.__name__ == "dict"

    def test__get_pricings__(self):
        defender = Defender(set_mocked_azure_audit_info())
        assert len(defender.pricings) == 1
        assert (
            defender.pricings[AZURE_SUSCRIPTION]["Standard"].resource_id
            == "resource_id"
        )
        assert (
            defender.pricings[AZURE_SUSCRIPTION]["Standard"].pricing_tier
            == "pricing_tier"
        )
        assert defender.pricings[AZURE_SUSCRIPTION][
            "Standard"
        ].free_trial_remaining_time == timedelta(days=1)

    def test__get_auto_provisioning_settings__(self):
        defender = Defender(set_mocked_azure_audit_info())
        assert len(defender.auto_provisioning_settings) == 1
        assert (
            defender.auto_provisioning_settings[AZURE_SUSCRIPTION][
                "default"
            ].resource_id
            == "/subscriptions/resource_id"
        )
        assert (
            defender.auto_provisioning_settings[AZURE_SUSCRIPTION][
                "default"
            ].resource_name
            == "default"
        )
        assert (
            defender.auto_provisioning_settings[AZURE_SUSCRIPTION][
                "default"
            ].resource_type
            == "Microsoft.Security/autoProvisioningSettings"
        )
        assert (
            defender.auto_provisioning_settings[AZURE_SUSCRIPTION][
                "default"
            ].auto_provision
            == "On"
        )

    def test__get_assessments__(self):
        defender = Defender(set_mocked_azure_audit_info())
        assert len(defender.assessments) == 1
        assert (
            defender.assessments[AZURE_SUSCRIPTION]["default"].resource_id
            == "/subscriptions/resource_id"
        )
        assert (
            defender.assessments[AZURE_SUSCRIPTION]["default"].resource_name
            == "default"
        )
        assert defender.assessments[AZURE_SUSCRIPTION]["default"].status == "Healthy"
