from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.defender.defender_service import Assesment
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_provider,
)


class Test_defender_assessments_vm_endpoint_protection_installed:
    def test_defender_no_subscriptions(self):
        defender_client = mock.MagicMock
        defender_client.assessments = {}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_assessments_vm_endpoint_protection_installed.defender_assessments_vm_endpoint_protection_installed.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_assessments_vm_endpoint_protection_installed.defender_assessments_vm_endpoint_protection_installed import (
                defender_assessments_vm_endpoint_protection_installed,
            )

            check = defender_assessments_vm_endpoint_protection_installed()
            result = check.execute()
            assert len(result) == 0

    def test_defender_subscriptions_with_no_assessments(self):
        defender_client = mock.MagicMock
        defender_client.assessments = {AZURE_SUBSCRIPTION: {}}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_assessments_vm_endpoint_protection_installed.defender_assessments_vm_endpoint_protection_installed.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_assessments_vm_endpoint_protection_installed.defender_assessments_vm_endpoint_protection_installed import (
                defender_assessments_vm_endpoint_protection_installed,
            )

            check = defender_assessments_vm_endpoint_protection_installed()
            result = check.execute()
            assert len(result) == 0

    def test_defender_subscriptions_with_healthy_assessments(self):
        defender_client = mock.MagicMock
        resource_id = str(uuid4())
        defender_client.assessments = {
            AZURE_SUBSCRIPTION: {
                "Install endpoint protection solution on virtual machines": Assesment(
                    resource_id=resource_id,
                    resource_name="vm1",
                    status="Healthy",
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_assessments_vm_endpoint_protection_installed.defender_assessments_vm_endpoint_protection_installed.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_assessments_vm_endpoint_protection_installed.defender_assessments_vm_endpoint_protection_installed import (
                defender_assessments_vm_endpoint_protection_installed,
            )

            check = defender_assessments_vm_endpoint_protection_installed()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Endpoint protection is set up in all VMs in subscription {AZURE_SUBSCRIPTION}."
            )
            assert result[0].resource_name == "vm1"
            assert result[0].resource_id == resource_id

    def test_defender_subscriptions_with_unhealthy_assessments(self):
        defender_client = mock.MagicMock
        resource_id = str(uuid4())
        defender_client.assessments = {
            AZURE_SUBSCRIPTION: {
                "Install endpoint protection solution on virtual machines": Assesment(
                    resource_id=resource_id,
                    resource_name="vm1",
                    status="Unhealthy",
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_assessments_vm_endpoint_protection_installed.defender_assessments_vm_endpoint_protection_installed.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_assessments_vm_endpoint_protection_installed.defender_assessments_vm_endpoint_protection_installed import (
                defender_assessments_vm_endpoint_protection_installed,
            )

            check = defender_assessments_vm_endpoint_protection_installed()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Endpoint protection is not set up in all VMs in subscription {AZURE_SUBSCRIPTION}."
            )
            assert result[0].resource_name == "vm1"
            assert result[0].resource_id == resource_id
