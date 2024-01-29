from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.defender.defender_service import (
    Defender_Assessments,
)
from tests.providers.azure.azure_fixtures import AZURE_SUSCRIPTION


class Test_defender_ensure_apply_system_updates_is_completed:
    def test_defender_no_app_services(self):
        defender_client = mock.MagicMock
        defender_client.assessments = {}

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_apply_system_updates_is_completed.defender_ensure_apply_system_updates_is_completed.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_apply_system_updates_is_completed.defender_ensure_apply_system_updates_is_completed import (
                defender_ensure_apply_system_updates_is_completed,
            )

            check = defender_ensure_apply_system_updates_is_completed()
            result = check.execute()
            assert len(result) == 0

    def test_defender_machines_no_configured_to_periodically_check_for_system_updates(
        self,
    ):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.assessments = {
            AZURE_SUSCRIPTION: {
                "Machines should be configured to periodically check for missing system updates": Defender_Assessments(
                    resource_id=resource_id,
                    resource_name="vm1",
                    status="Unhealthy",
                ),
                "System updates should be installed on your machines": Defender_Assessments(
                    resource_id=resource_id,
                    resource_name="vm1",
                    status="Healthy",
                ),
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_apply_system_updates_is_completed.defender_ensure_apply_system_updates_is_completed.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_apply_system_updates_is_completed.defender_ensure_apply_system_updates_is_completed import (
                defender_ensure_apply_system_updates_is_completed,
            )

            check = defender_ensure_apply_system_updates_is_completed()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Apply system updates assessment is UNHEALTHY for subscription {AZURE_SUSCRIPTION}."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == "vm1"
            assert result[0].resource_id == resource_id

    def test_defender_machines_no_system_updates_installed(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.assessments = {
            AZURE_SUSCRIPTION: {
                "Machines should be configured to periodically check for missing system updates": Defender_Assessments(
                    resource_id=resource_id,
                    resource_name="vm1",
                    status="Healthy",
                ),
                "System updates should be installed on your machines": Defender_Assessments(
                    resource_id=resource_id,
                    resource_name="vm1",
                    status="Unhealthy",
                ),
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_apply_system_updates_is_completed.defender_ensure_apply_system_updates_is_completed.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_apply_system_updates_is_completed.defender_ensure_apply_system_updates_is_completed import (
                defender_ensure_apply_system_updates_is_completed,
            )

            check = defender_ensure_apply_system_updates_is_completed()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Apply system updates assessment is UNHEALTHY for subscription {AZURE_SUSCRIPTION}."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == "vm1"
            assert result[0].resource_id == resource_id

    def test_defender_machines_configured_to_periodically_check_for_system_updates_and_system_updates_installed(
        self,
    ):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.assessments = {
            AZURE_SUSCRIPTION: {
                "Machines should be configured to periodically check for missing system updates": Defender_Assessments(
                    resource_id=resource_id,
                    resource_name="vm1",
                    status="Healthy",
                ),
                "System updates should be installed on your machines": Defender_Assessments(
                    resource_id=resource_id,
                    resource_name="vm1",
                    status="Healthy",
                ),
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_ensure_apply_system_updates_is_completed.defender_ensure_apply_system_updates_is_completed.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_ensure_apply_system_updates_is_completed.defender_ensure_apply_system_updates_is_completed import (
                defender_ensure_apply_system_updates_is_completed,
            )

            check = defender_ensure_apply_system_updates_is_completed()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Apply system updates assessment is HEALTHY for subscription {AZURE_SUSCRIPTION}."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == "vm1"
            assert result[0].resource_id == resource_id
