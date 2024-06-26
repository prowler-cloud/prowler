from datetime import timedelta
from unittest.mock import patch

from prowler.providers.azure.services.defender.defender_service import (
    Assesment,
    AutoProvisioningSetting,
    Defender,
    IoTSecuritySolution,
    Pricing,
    SecurityContacts,
    Setting,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


def mock_defender_get_pricings(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "Standard": Pricing(
                resource_id="resource_id",
                pricing_tier="pricing_tier",
                free_trial_remaining_time=timedelta(days=1),
                extensions={},
            )
        }
    }


def mock_defender_get_auto_provisioning_settings(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
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
        AZURE_SUBSCRIPTION_ID: {
            "default": Assesment(
                resource_id="/subscriptions/resource_id",
                resource_name="default",
                status="Healthy",
            )
        }
    }


def mock_defender_get_security_contacts(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "default": SecurityContacts(
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


def mock_defender_get_settings(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "MCAS": Setting(
                resource_id="/subscriptions/resource_id",
                resource_type="Microsoft.Security/locations/settings",
                kind="DataExportSettings",
                enabled=True,
            )
        }
    }


def mock_defender_get_iot_security_solutions(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "iot_sec_solution": IoTSecuritySolution(
                resource_id="/subscriptions/resource_id",
                status="Enabled",
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
    "prowler.providers.azure.services.defender.defender_service.Defender.__get_settings__",
    new=mock_defender_get_settings,
)
@patch(
    "prowler.providers.azure.services.defender.defender_service.Defender.__get_security_contacts__",
    new=mock_defender_get_security_contacts,
)
@patch(
    "prowler.providers.azure.services.defender.defender_service.Defender.__get_iot_security_solutions__",
    new=mock_defender_get_iot_security_solutions,
)
class Test_Defender_Service:
    def test__get_client__(self):
        defender = Defender(set_mocked_azure_provider())
        assert (
            defender.clients[AZURE_SUBSCRIPTION_ID].__class__.__name__
            == "SecurityCenter"
        )

    def test__get_subscriptions__(self):
        defender = Defender(set_mocked_azure_provider())
        defender = Defender(set_mocked_azure_provider())
        assert defender.subscriptions.__class__.__name__ == "dict"

    def test__get_pricings__(self):
        defender = Defender(set_mocked_azure_provider())
        assert len(defender.pricings) == 1
        assert (
            defender.pricings[AZURE_SUBSCRIPTION_ID]["Standard"].resource_id
            == "resource_id"
        )
        assert (
            defender.pricings[AZURE_SUBSCRIPTION_ID]["Standard"].pricing_tier
            == "pricing_tier"
        )
        assert defender.pricings[AZURE_SUBSCRIPTION_ID][
            "Standard"
        ].free_trial_remaining_time == timedelta(days=1)
        assert defender.pricings[AZURE_SUBSCRIPTION_ID]["Standard"].extensions == {}

    def test__get_auto_provisioning_settings__(self):
        defender = Defender(set_mocked_azure_provider())
        assert len(defender.auto_provisioning_settings) == 1
        assert (
            defender.auto_provisioning_settings[AZURE_SUBSCRIPTION_ID][
                "default"
            ].resource_id
            == "/subscriptions/resource_id"
        )
        assert (
            defender.auto_provisioning_settings[AZURE_SUBSCRIPTION_ID][
                "default"
            ].resource_name
            == "default"
        )
        assert (
            defender.auto_provisioning_settings[AZURE_SUBSCRIPTION_ID][
                "default"
            ].resource_type
            == "Microsoft.Security/autoProvisioningSettings"
        )
        assert (
            defender.auto_provisioning_settings[AZURE_SUBSCRIPTION_ID][
                "default"
            ].auto_provision
            == "On"
        )

    def test__get_assessments__(self):
        defender = Defender(set_mocked_azure_provider())
        assert len(defender.assessments) == 1
        assert (
            defender.assessments[AZURE_SUBSCRIPTION_ID]["default"].resource_id
            == "/subscriptions/resource_id"
        )
        assert (
            defender.assessments[AZURE_SUBSCRIPTION_ID]["default"].resource_name
            == "default"
        )
        assert (
            defender.assessments[AZURE_SUBSCRIPTION_ID]["default"].status == "Healthy"
        )

    def test__get_settings__(self):
        defender = Defender(set_mocked_azure_provider())
        assert len(defender.settings) == 1
        assert (
            defender.settings[AZURE_SUBSCRIPTION_ID]["MCAS"].resource_id
            == "/subscriptions/resource_id"
        )
        assert (
            defender.settings[AZURE_SUBSCRIPTION_ID]["MCAS"].resource_type
            == "Microsoft.Security/locations/settings"
        )
        assert (
            defender.settings[AZURE_SUBSCRIPTION_ID]["MCAS"].kind
            == "DataExportSettings"
        )
        assert defender.settings[AZURE_SUBSCRIPTION_ID]["MCAS"].enabled

    def test__get_security_contacts__(self):
        defender = Defender(set_mocked_azure_provider())
        assert len(defender.security_contacts) == 1
        assert (
            defender.security_contacts[AZURE_SUBSCRIPTION_ID]["default"].resource_id
            == "/subscriptions/resource_id"
        )
        assert (
            defender.security_contacts[AZURE_SUBSCRIPTION_ID]["default"].emails
            == "user@user.com, test@test.es"
        )
        assert (
            defender.security_contacts[AZURE_SUBSCRIPTION_ID]["default"].phone
            == "666666666"
        )
        assert (
            defender.security_contacts[AZURE_SUBSCRIPTION_ID][
                "default"
            ].alert_notifications_minimal_severity
            == "High"
        )
        assert (
            defender.security_contacts[AZURE_SUBSCRIPTION_ID][
                "default"
            ].alert_notifications_state
            == "On"
        )
        assert defender.security_contacts[AZURE_SUBSCRIPTION_ID][
            "default"
        ].notified_roles == ["Owner", "Contributor"]
        assert (
            defender.security_contacts[AZURE_SUBSCRIPTION_ID][
                "default"
            ].notified_roles_state
            == "On"
        )

    def test__get_iot_security_solutions__(self):
        defender = Defender(set_mocked_azure_provider())
        assert len(defender.iot_security_solutions) == 1
        assert (
            defender.iot_security_solutions[AZURE_SUBSCRIPTION_ID][
                "iot_sec_solution"
            ].resource_id
            == "/subscriptions/resource_id"
        )
        assert (
            defender.iot_security_solutions[AZURE_SUBSCRIPTION_ID][
                "iot_sec_solution"
            ].status
            == "Enabled"
        )
