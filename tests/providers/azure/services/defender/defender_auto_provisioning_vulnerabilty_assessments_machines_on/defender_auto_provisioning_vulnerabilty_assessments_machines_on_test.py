from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.defender.defender_service import Assesment
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_defender_auto_provisioning_vulnerabilty_assessments_machines_on:
    def test_defender_no_app_services(self):
        defender_client = mock.MagicMock
        defender_client.assessments = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_auto_provisioning_vulnerabilty_assessments_machines_on.defender_auto_provisioning_vulnerabilty_assessments_machines_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_auto_provisioning_vulnerabilty_assessments_machines_on.defender_auto_provisioning_vulnerabilty_assessments_machines_on import (
                defender_auto_provisioning_vulnerabilty_assessments_machines_on,
            )

            check = defender_auto_provisioning_vulnerabilty_assessments_machines_on()
            result = check.execute()
            assert len(result) == 0

    def test_defender_machines_no_vulnerability_assessment_solution(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.assessments = {
            AZURE_SUBSCRIPTION_ID: {
                "Machines should have a vulnerability assessment solution": Assesment(
                    resource_id=resource_id,
                    resource_name="vm1",
                    status="Unhealthy",
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_auto_provisioning_vulnerabilty_assessments_machines_on.defender_auto_provisioning_vulnerabilty_assessments_machines_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_auto_provisioning_vulnerabilty_assessments_machines_on.defender_auto_provisioning_vulnerabilty_assessments_machines_on import (
                defender_auto_provisioning_vulnerabilty_assessments_machines_on,
            )

            check = defender_auto_provisioning_vulnerabilty_assessments_machines_on()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Vulnerability assessment is not set up in all VMs in subscription {AZURE_SUBSCRIPTION_ID}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "vm1"
            assert result[0].resource_id == resource_id

    def test_defender_machines_vulnerability_assessment_solution(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.assessments = {
            AZURE_SUBSCRIPTION_ID: {
                "Machines should have a vulnerability assessment solution": Assesment(
                    resource_id=resource_id,
                    resource_name="vm1",
                    status="Healthy",
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_auto_provisioning_vulnerabilty_assessments_machines_on.defender_auto_provisioning_vulnerabilty_assessments_machines_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_auto_provisioning_vulnerabilty_assessments_machines_on.defender_auto_provisioning_vulnerabilty_assessments_machines_on import (
                defender_auto_provisioning_vulnerabilty_assessments_machines_on,
            )

            check = defender_auto_provisioning_vulnerabilty_assessments_machines_on()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Vulnerability assessment is set up in all VMs in subscription {AZURE_SUBSCRIPTION_ID}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "vm1"
            assert result[0].resource_id == resource_id
