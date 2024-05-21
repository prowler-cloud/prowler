from datetime import timedelta
from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.defender.defender_service import Pricing
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_defender_container_images_scan_enabled:
    def test_defender_no_subscriptions(self):
        defender_client = mock.MagicMock
        defender_client.pricings = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_container_images_scan_enabled.defender_container_images_scan_enabled.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_container_images_scan_enabled.defender_container_images_scan_enabled import (
                defender_container_images_scan_enabled,
            )

            check = defender_container_images_scan_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_defender_subscription_empty(self):
        defender_client = mock.MagicMock
        defender_client.pricings = {AZURE_SUBSCRIPTION_ID: {}}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_container_images_scan_enabled.defender_container_images_scan_enabled.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_container_images_scan_enabled.defender_container_images_scan_enabled import (
                defender_container_images_scan_enabled,
            )

            check = defender_container_images_scan_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_defender_subscription_no_containers(self):
        defender_client = mock.MagicMock
        defender_client.pricings = {
            AZURE_SUBSCRIPTION_ID: {
                "NotContainers": Pricing(
                    resource_id=str(uuid4()),
                    pricing_tier="Free",
                    free_trial_remaining_time=timedelta(days=1),
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_container_images_scan_enabled.defender_container_images_scan_enabled.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_container_images_scan_enabled.defender_container_images_scan_enabled import (
                defender_container_images_scan_enabled,
            )

            check = defender_container_images_scan_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_defender_subscription_containers_no_extensions(self):
        defender_client = mock.MagicMock
        defender_client.pricings = {
            AZURE_SUBSCRIPTION_ID: {
                "Containers": Pricing(
                    resource_id=str(uuid4()),
                    pricing_tier="Free",
                    free_trial_remaining_time=timedelta(days=1),
                    extensions={},
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_container_images_scan_enabled.defender_container_images_scan_enabled.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_container_images_scan_enabled.defender_container_images_scan_enabled import (
                defender_container_images_scan_enabled,
            )

            check = defender_container_images_scan_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"Container image scan is disabled in subscription {AZURE_SUBSCRIPTION_ID}."
            )
            assert (
                result[0].resource_id
                == defender_client.pricings[AZURE_SUBSCRIPTION_ID][
                    "Containers"
                ].resource_id
            )
            assert result[0].resource_name == "Dender plan for Containers"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_defender_subscription_containers_container_images_scan_off(self):
        defender_client = mock.MagicMock
        defender_client.pricings = {
            AZURE_SUBSCRIPTION_ID: {
                "Containers": Pricing(
                    resource_id=str(uuid4()),
                    pricing_tier="Free",
                    free_trial_remaining_time=timedelta(days=1),
                    extensions={"ContainerRegistriesVulnerabilityAssessments": False},
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_container_images_scan_enabled.defender_container_images_scan_enabled.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_container_images_scan_enabled.defender_container_images_scan_enabled import (
                defender_container_images_scan_enabled,
            )

            check = defender_container_images_scan_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"Container image scan is disabled in subscription {AZURE_SUBSCRIPTION_ID}."
            )
            assert (
                result[0].resource_id
                == defender_client.pricings[AZURE_SUBSCRIPTION_ID][
                    "Containers"
                ].resource_id
            )
            assert result[0].resource_name == "Dender plan for Containers"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_defender_subscription_containers_container_images_scan_on(self):
        defender_client = mock.MagicMock
        defender_client.pricings = {
            AZURE_SUBSCRIPTION_ID: {
                "Containers": Pricing(
                    resource_id=str(uuid4()),
                    pricing_tier="Free",
                    free_trial_remaining_time=timedelta(days=1),
                    extensions={"ContainerRegistriesVulnerabilityAssessments": True},
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_container_images_scan_enabled.defender_container_images_scan_enabled.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_container_images_scan_enabled.defender_container_images_scan_enabled import (
                defender_container_images_scan_enabled,
            )

            check = defender_container_images_scan_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"Container image scan is enabled in subscription {AZURE_SUBSCRIPTION_ID}."
            )
            assert (
                result[0].resource_id
                == defender_client.pricings[AZURE_SUBSCRIPTION_ID][
                    "Containers"
                ].resource_id
            )
            assert result[0].resource_name == "Dender plan for Containers"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
