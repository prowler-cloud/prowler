from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.defender.defender_service import Assesment
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_defender_container_images_resolved_vulnerabilities:
    def test_defender_no_subscriptions(self):
        defender_client = mock.MagicMock
        defender_client.assessments = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_container_images_resolved_vulnerabilities.defender_container_images_resolved_vulnerabilities.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_container_images_resolved_vulnerabilities.defender_container_images_resolved_vulnerabilities import (
                defender_container_images_resolved_vulnerabilities,
            )

            check = defender_container_images_resolved_vulnerabilities()
            result = check.execute()
            assert len(result) == 0

    def test_defender_subscription_empty(self):
        defender_client = mock.MagicMock
        defender_client.assessments = {AZURE_SUBSCRIPTION_ID: {}}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_container_images_resolved_vulnerabilities.defender_container_images_resolved_vulnerabilities.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_container_images_resolved_vulnerabilities.defender_container_images_resolved_vulnerabilities import (
                defender_container_images_resolved_vulnerabilities,
            )

            check = defender_container_images_resolved_vulnerabilities()
            result = check.execute()
            assert len(result) == 0

    def test_defender_subscription_no_assesment(self):
        defender_client = mock.MagicMock
        defender_client.assessments = {
            AZURE_SUBSCRIPTION_ID: {
                "": Assesment(
                    resource_id=str(uuid4()),
                    resource_name=str(uuid4()),
                    status="Unhealthy",
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_container_images_resolved_vulnerabilities.defender_container_images_resolved_vulnerabilities.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_container_images_resolved_vulnerabilities.defender_container_images_resolved_vulnerabilities import (
                defender_container_images_resolved_vulnerabilities,
            )

            check = defender_container_images_resolved_vulnerabilities()
            result = check.execute()
            assert len(result) == 0

    def test_defender_subscription_assesment_unhealthy(self):
        defender_client = mock.MagicMock
        defender_client.assessments = {
            AZURE_SUBSCRIPTION_ID: {
                "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)": Assesment(
                    resource_id=str(uuid4()),
                    resource_name=str(uuid4()),
                    status="Unhealthy",
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_container_images_resolved_vulnerabilities.defender_container_images_resolved_vulnerabilities.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_container_images_resolved_vulnerabilities.defender_container_images_resolved_vulnerabilities import (
                defender_container_images_resolved_vulnerabilities,
            )

            check = defender_container_images_resolved_vulnerabilities()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].resource_id
                == defender_client.assessments[AZURE_SUBSCRIPTION_ID][
                    "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
                ].resource_id
            )
            assert (
                result[0].resource_name
                == defender_client.assessments[AZURE_SUBSCRIPTION_ID][
                    "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
                ].resource_name
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert (
                result[0].status_extended
                == f"Azure running container images have unresolved vulnerabilities in subscription '{AZURE_SUBSCRIPTION_ID}'."
            )

    def test_defender_subscription_assesment_healthy(self):
        defender_client = mock.MagicMock
        defender_client.assessments = {
            AZURE_SUBSCRIPTION_ID: {
                "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)": Assesment(
                    resource_id=str(uuid4()),
                    resource_name=str(uuid4()),
                    status="Healthy",
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_container_images_resolved_vulnerabilities.defender_container_images_resolved_vulnerabilities.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_container_images_resolved_vulnerabilities.defender_container_images_resolved_vulnerabilities import (
                defender_container_images_resolved_vulnerabilities,
            )

            check = defender_container_images_resolved_vulnerabilities()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].resource_id
                == defender_client.assessments[AZURE_SUBSCRIPTION_ID][
                    "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
                ].resource_id
            )
            assert (
                result[0].resource_name
                == defender_client.assessments[AZURE_SUBSCRIPTION_ID][
                    "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
                ].resource_name
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert (
                result[0].status_extended
                == f"Azure running container images do not have unresolved vulnerabilities in subscription '{AZURE_SUBSCRIPTION_ID}'."
            )

    def test_defender_subscription_assesment_not_applicable(self):
        defender_client = mock.MagicMock
        defender_client.assessments = {
            AZURE_SUBSCRIPTION_ID: {
                "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)": Assesment(
                    resource_id=str(uuid4()),
                    resource_name=str(uuid4()),
                    status="NotApplicable",
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_container_images_resolved_vulnerabilities.defender_container_images_resolved_vulnerabilities.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_container_images_resolved_vulnerabilities.defender_container_images_resolved_vulnerabilities import (
                defender_container_images_resolved_vulnerabilities,
            )

            check = defender_container_images_resolved_vulnerabilities()
            result = check.execute()
            assert len(result) == 0
