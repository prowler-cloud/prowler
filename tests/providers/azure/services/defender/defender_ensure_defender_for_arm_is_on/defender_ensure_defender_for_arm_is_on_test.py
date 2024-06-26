from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.defender.defender_service import Pricing
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_defender_ensure_defender_for_arm_is_on:
    def test_defender_no_arm(self):
        defender_client = mock.MagicMock
        defender_client.pricings = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_defender_for_arm_is_on.defender_ensure_defender_for_arm_is_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_defender_for_arm_is_on.defender_ensure_defender_for_arm_is_on import (
                defender_ensure_defender_for_arm_is_on,
            )

            check = defender_ensure_defender_for_arm_is_on()
            result = check.execute()
            assert len(result) == 0

    def test_defender_arm_pricing_tier_not_standard(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.pricings = {
            AZURE_SUBSCRIPTION_ID: {
                "Arm": Pricing(
                    resource_id=resource_id,
                    pricing_tier="Not Standard",
                    free_trial_remaining_time=0,
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_defender_for_arm_is_on.defender_ensure_defender_for_arm_is_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_defender_for_arm_is_on.defender_ensure_defender_for_arm_is_on import (
                defender_ensure_defender_for_arm_is_on,
            )

            check = defender_ensure_defender_for_arm_is_on()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Defender plan Defender for ARM from subscription {AZURE_SUBSCRIPTION_ID} is set to OFF (pricing tier not standard)."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "Defender plan ARM"
            assert result[0].resource_id == resource_id

    def test_defender_arm_pricing_tier_standard(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.pricings = {
            AZURE_SUBSCRIPTION_ID: {
                "Arm": Pricing(
                    resource_id=resource_id,
                    pricing_tier="Standard",
                    free_trial_remaining_time=0,
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_defender_for_arm_is_on.defender_ensure_defender_for_arm_is_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_defender_for_arm_is_on.defender_ensure_defender_for_arm_is_on import (
                defender_ensure_defender_for_arm_is_on,
            )

            check = defender_ensure_defender_for_arm_is_on()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Defender plan Defender for ARM from subscription {AZURE_SUBSCRIPTION_ID} is set to ON (pricing tier standard)."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "Defender plan ARM"
            assert result[0].resource_id == resource_id
