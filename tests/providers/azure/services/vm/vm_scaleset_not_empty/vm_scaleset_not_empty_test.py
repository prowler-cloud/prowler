from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.vm.vm_service import VirtualMachineScaleSet
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_vm_scaleset_not_empty:
    def test_no_subscriptions(self):
        vm_scale_sets = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_client.vm_client.vm_scale_sets",
                new=vm_scale_sets,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_scaleset_not_empty.vm_scaleset_not_empty import (
                vm_scaleset_not_empty,
            )

            check = vm_scaleset_not_empty()
            result = check.execute()
            assert len(result) == 0

    def test_empty_scale_sets(self):
        vm_scale_sets = {AZURE_SUBSCRIPTION_ID: {}}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_client.vm_client.vm_scale_sets",
                new=vm_scale_sets,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_scaleset_not_empty.vm_scaleset_not_empty import (
                vm_scaleset_not_empty,
            )

            check = vm_scaleset_not_empty()
            result = check.execute()
            assert len(result) == 0

    def test_scale_set_with_no_instances(self):
        vmss_id = str(uuid4())
        vm_scale_sets = {
            AZURE_SUBSCRIPTION_ID: {
                vmss_id: VirtualMachineScaleSet(
                    resource_id=vmss_id,
                    resource_name="empty-vmss",
                    location="eastus",
                    load_balancer_backend_pools=[],
                    instance_ids=[],
                )
            }
        }
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_client.vm_client.vm_scale_sets",
                new=vm_scale_sets,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_scaleset_not_empty.vm_scaleset_not_empty import (
                vm_scaleset_not_empty,
            )

            check = vm_scaleset_not_empty()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == vmss_id
            assert result[0].resource_name == "empty-vmss"
            assert result[0].location == "eastus"
            expected_status_extended = f"Scale set 'empty-vmss' in subscription '{AZURE_SUBSCRIPTION_ID}' is empty: no VM instances present."
            assert result[0].status_extended == expected_status_extended

    def test_scale_set_with_instances(self):
        vmss_id = str(uuid4())
        instance_ids = ["1", "2"]
        vm_scale_sets = {
            AZURE_SUBSCRIPTION_ID: {
                vmss_id: VirtualMachineScaleSet(
                    resource_id=vmss_id,
                    resource_name="nonempty-vmss",
                    location="westeurope",
                    load_balancer_backend_pools=[],
                    instance_ids=instance_ids,
                )
            }
        }
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_client.vm_client.vm_scale_sets",
                new=vm_scale_sets,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_scaleset_not_empty.vm_scaleset_not_empty import (
                vm_scaleset_not_empty,
            )

            check = vm_scaleset_not_empty()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == vmss_id
            assert result[0].resource_name == "nonempty-vmss"
            assert result[0].location == "westeurope"
            expected_status_extended = f"Scale set 'nonempty-vmss' in subscription '{AZURE_SUBSCRIPTION_ID}' has {len(instance_ids)} VM instances."
            assert result[0].status_extended == expected_status_extended

    def test_multiple_scale_sets(self):
        empty_id = str(uuid4())
        nonempty_id = str(uuid4())
        instance_ids = ["1"]
        vm_scale_sets = {
            AZURE_SUBSCRIPTION_ID: {
                empty_id: VirtualMachineScaleSet(
                    resource_id=empty_id,
                    resource_name="empty-vmss",
                    location="eastus",
                    load_balancer_backend_pools=[],
                    instance_ids=[],
                ),
                nonempty_id: VirtualMachineScaleSet(
                    resource_id=nonempty_id,
                    resource_name="nonempty-vmss",
                    location="westeurope",
                    load_balancer_backend_pools=[],
                    instance_ids=instance_ids,
                ),
            }
        }
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_client.vm_client.vm_scale_sets",
                new=vm_scale_sets,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_scaleset_not_empty.vm_scaleset_not_empty import (
                vm_scaleset_not_empty,
            )

            check = vm_scaleset_not_empty()
            result = check.execute()
            assert len(result) == 2
            for r in result:
                if r.resource_name == "empty-vmss":
                    expected_status_extended = f"Scale set 'empty-vmss' in subscription '{AZURE_SUBSCRIPTION_ID}' is empty: no VM instances present."
                    assert r.status == "FAIL"
                    assert r.status_extended == expected_status_extended
                elif r.resource_name == "nonempty-vmss":
                    expected_status_extended = f"Scale set 'nonempty-vmss' in subscription '{AZURE_SUBSCRIPTION_ID}' has {len(instance_ids)} VM instances."
                    assert r.status == "PASS"
                    assert r.status_extended == expected_status_extended
