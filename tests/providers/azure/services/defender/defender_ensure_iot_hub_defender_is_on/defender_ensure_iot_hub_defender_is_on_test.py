from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.defender.defender_service import (
    IotSecuritySolution,
)
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION


class Test_defender_ensure_iot_hub_defender_is_on:
    def test_defender_no_iot_hub_solutions(self):
        defender_client = mock.MagicMock
        defender_client.iot_security_solutions = {}

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_iot_hub_defender_is_on.defender_ensure_iot_hub_defender_is_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_iot_hub_defender_is_on.defender_ensure_iot_hub_defender_is_on import (
                defender_ensure_iot_hub_defender_is_on,
            )

            check = defender_ensure_iot_hub_defender_is_on()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "No IoT Security Solutions found."
            assert result[0].resource_name == "IoT Hub Defender"
            assert result[0].resource_id == "IoT Hub Defender"

    def test_defender_iot_hub_solution_disabled(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.iot_security_solutions = {
            AZURE_SUBSCRIPTION: {
                "iot_sec_solution": IotSecuritySolution(
                    resource_id=resource_id, status="Disabled"
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_iot_hub_defender_is_on.defender_ensure_iot_hub_defender_is_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_iot_hub_defender_is_on.defender_ensure_iot_hub_defender_is_on import (
                defender_ensure_iot_hub_defender_is_on,
            )

            check = defender_ensure_iot_hub_defender_is_on()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"The security solution iot_sec_solution is not enabled for susbscription {AZURE_SUBSCRIPTION}"
            )
            assert result[0].resource_name == "iot_sec_solution"
            assert result[0].resource_id == resource_id

    def test_defender_iot_hub_solution_enabled(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.iot_security_solutions = {
            AZURE_SUBSCRIPTION: {
                "iot_sec_solution": IotSecuritySolution(
                    resource_id=resource_id, status="Enabled"
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_iot_hub_defender_is_on.defender_ensure_iot_hub_defender_is_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_iot_hub_defender_is_on.defender_ensure_iot_hub_defender_is_on import (
                defender_ensure_iot_hub_defender_is_on,
            )

            check = defender_ensure_iot_hub_defender_is_on()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"The security solution iot_sec_solution is enabled for susbscription {AZURE_SUBSCRIPTION}."
            )
            assert result[0].resource_name == "iot_sec_solution"
            assert result[0].resource_id == resource_id
            assert result[0].subscription == AZURE_SUBSCRIPTION

    def test_defender_multiple_iot_hub_solution_enabled_and_disabled(self):
        resource_id_enabled = str(uuid4())
        resource_id_disabled = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.iot_security_solutions = {
            AZURE_SUBSCRIPTION: {
                "iot_sec_solution_enabled": IotSecuritySolution(
                    resource_id=resource_id_enabled, status="Enabled"
                ),
                "iot_sec_solution_disabled": IotSecuritySolution(
                    resource_id=resource_id_disabled, status="Disabled"
                ),
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_iot_hub_defender_is_on.defender_ensure_iot_hub_defender_is_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_iot_hub_defender_is_on.defender_ensure_iot_hub_defender_is_on import (
                defender_ensure_iot_hub_defender_is_on,
            )

            check = defender_ensure_iot_hub_defender_is_on()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"The security solution iot_sec_solution_enabled is enabled for susbscription {AZURE_SUBSCRIPTION}."
            )
            assert result[0].resource_name == "iot_sec_solution_enabled"
            assert result[0].resource_id == resource_id_enabled
            assert result[0].subscription == AZURE_SUBSCRIPTION

            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == f"The security solution iot_sec_solution_disabled is not enabled for susbscription {AZURE_SUBSCRIPTION}"
            )
            assert result[1].resource_name == "iot_sec_solution_disabled"
            assert result[1].resource_id == resource_id_disabled
            assert result[1].subscription == AZURE_SUBSCRIPTION
