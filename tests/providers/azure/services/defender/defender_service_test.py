from datetime import timedelta
from unittest.mock import patch

from prowler.providers.azure.services.defender.defender_service import (
    AutoProvisioningSetting,
    Defender,
    Defender_Assessments,
    Defender_Pricing,
    Defender_Security_Contacts,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUSCRIPTION,
    set_mocked_azure_audit_info,
)


def mock_defender_get_pricings(_):
    return {
        AZURE_SUSCRIPTION: {
            "Standard": Defender_Pricing(
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
            "default": Defender_Assessments(
                resource_id="/subscriptions/resource_id",
                resource_name="default",
                status="Healthy",
            )
        }
    }


def mock_defender_get_security_contacts(_):
    return {
        AZURE_SUSCRIPTION: {
            "default": Defender_Security_Contacts(
                resource_id="/subscriptions/resource_id",
                emails="user@user.com, test@test.es",
                phone="666666666",
                alert_notifications_minimal_severity="High",
                alert_notifications_state="On",
                notified_roles=["Owner", "Contributor"],
                notified_roles_state="On",
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
@patch(
    "prowler.providers.azure.services.defender.defender_service.Defender.__get_security_contacts__",
    new=mock_defender_get_security_contacts,
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

    def test__get_security_contacts__(self):
        defender = Defender(set_mocked_azure_audit_info())
        assert len(defender.security_contacts) == 1
        assert (
            defender.security_contacts[AZURE_SUSCRIPTION]["default"].resource_id
            == "/subscriptions/resource_id"
        )
        assert (
            defender.security_contacts[AZURE_SUSCRIPTION]["default"].emails
            == "user@user.com, test@test.es"
        )
        assert (
            defender.security_contacts[AZURE_SUSCRIPTION]["default"].phone
            == "666666666"
        )
        assert (
            defender.security_contacts[AZURE_SUSCRIPTION][
                "default"
            ].alert_notifications_minimal_severity
            == "High"
        )
        assert (
            defender.security_contacts[AZURE_SUSCRIPTION][
                "default"
            ].alert_notifications_state
            == "On"
        )
        assert defender.security_contacts[AZURE_SUSCRIPTION][
            "default"
        ].notified_roles == ["Owner", "Contributor"]
        assert (
            defender.security_contacts[AZURE_SUSCRIPTION][
                "default"
            ].notified_roles_state
            == "On"
        )
