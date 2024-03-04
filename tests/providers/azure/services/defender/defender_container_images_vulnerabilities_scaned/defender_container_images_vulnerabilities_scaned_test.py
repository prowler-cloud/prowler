from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.defender.defender_service import Assesment
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION


class Test_defender_container_images_vulnerabilities_scaned:
    def test_defender_no_subscriptions(self):
        defender_client = mock.MagicMock
        defender_client.assessments = {}

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_container_images_vulnerabilities_scaned.defender_container_images_vulnerabilities_scaned.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_container_images_vulnerabilities_scaned.defender_container_images_vulnerabilities_scaned import (
                defender_container_images_vulnerabilities_scaned,
            )

            check = defender_container_images_vulnerabilities_scaned()
            result = check.execute()
            assert len(result) == 0

    def test_defender_subscription_empty(self):
        defender_client = mock.MagicMock
        defender_client.assessments = {AZURE_SUBSCRIPTION: {}}

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_container_images_vulnerabilities_scaned.defender_container_images_vulnerabilities_scaned.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_container_images_vulnerabilities_scaned.defender_container_images_vulnerabilities_scaned import (
                defender_container_images_vulnerabilities_scaned,
            )

            check = defender_container_images_vulnerabilities_scaned()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "Microsoft.Security/assessments"
            assert result[0].resource_name == "Microsoft.Security/assessments"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert (
                result[0].status_extended
                == f"Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management) is not enabled in subscription '{AZURE_SUBSCRIPTION}'."
            )

    def test_defender_subscription_no_assesment(self):
        defender_client = mock.MagicMock
        defender_client.assessments = {
            AZURE_SUBSCRIPTION: {
                "": Assesment(
                    resource_id=str(uuid4()),
                    resource_name=str(uuid4()),
                    status="Unhealthy",
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_container_images_vulnerabilities_scaned.defender_container_images_vulnerabilities_scaned.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_container_images_vulnerabilities_scaned.defender_container_images_vulnerabilities_scaned import (
                defender_container_images_vulnerabilities_scaned,
            )

            check = defender_container_images_vulnerabilities_scaned()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "Microsoft.Security/assessments"
            assert result[0].resource_name == "Microsoft.Security/assessments"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert (
                result[0].status_extended
                == f"Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management) is not enabled in subscription '{AZURE_SUBSCRIPTION}'."
            )

    def test_defender_subscription_assesment_unhealthy(self):
        defender_client = mock.MagicMock
        defender_client.assessments = {
            AZURE_SUBSCRIPTION: {
                "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)": Assesment(
                    resource_id=str(uuid4()),
                    resource_name=str(uuid4()),
                    status="Unhealthy",
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_container_images_vulnerabilities_scaned.defender_container_images_vulnerabilities_scaned.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_container_images_vulnerabilities_scaned.defender_container_images_vulnerabilities_scaned import (
                defender_container_images_vulnerabilities_scaned,
            )

            check = defender_container_images_vulnerabilities_scaned()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].resource_id
                == defender_client.assessments[AZURE_SUBSCRIPTION][
                    "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
                ].resource_id
            )
            assert (
                result[0].resource_name
                == defender_client.assessments[AZURE_SUBSCRIPTION][
                    "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
                ].resource_name
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert (
                result[0].status_extended
                == f"Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management) is not enabled in subscription '{AZURE_SUBSCRIPTION}'."
            )

    def test_defender_subscription_assesment_healthy(self):
        defender_client = mock.MagicMock
        defender_client.assessments = {
            AZURE_SUBSCRIPTION: {
                "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)": Assesment(
                    resource_id=str(uuid4()),
                    resource_name=str(uuid4()),
                    status="Healthy",
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_container_images_vulnerabilities_scaned.defender_container_images_vulnerabilities_scaned.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_container_images_vulnerabilities_scaned.defender_container_images_vulnerabilities_scaned import (
                defender_container_images_vulnerabilities_scaned,
            )

            check = defender_container_images_vulnerabilities_scaned()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].resource_id
                == defender_client.assessments[AZURE_SUBSCRIPTION][
                    "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
                ].resource_id
            )
            assert (
                result[0].resource_name
                == defender_client.assessments[AZURE_SUBSCRIPTION][
                    "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
                ].resource_name
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert (
                result[0].status_extended
                == f"Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management) is enabled in subscription '{AZURE_SUBSCRIPTION}'."
            )
