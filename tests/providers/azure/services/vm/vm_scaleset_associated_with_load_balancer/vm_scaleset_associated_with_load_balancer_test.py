from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.vm.vm_service import VirtualMachineScaleSet
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_vm_scaleset_associated_with_load_balancer:
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
            from prowler.providers.azure.services.vm.vm_scaleset_associated_with_load_balancer.vm_scaleset_associated_with_load_balancer import (
                vm_scaleset_associated_with_load_balancer,
            )

            check = vm_scaleset_associated_with_load_balancer()
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
            from prowler.providers.azure.services.vm.vm_scaleset_associated_with_load_balancer.vm_scaleset_associated_with_load_balancer import (
                vm_scaleset_associated_with_load_balancer,
            )

            check = vm_scaleset_associated_with_load_balancer()
            result = check.execute()
            assert len(result) == 0

    def test_compliant_scale_set(self):
        vmss_id = str(uuid4())
        backend_pool_id = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb/backendAddressPools/bepool"
        vm_scale_sets = {
            AZURE_SUBSCRIPTION_ID: {
                vmss_id: VirtualMachineScaleSet(
                    resource_id=vmss_id,
                    resource_name="compliant-vmss",
                    location="eastus",
                    load_balancer_backend_pools=[backend_pool_id],
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
            from prowler.providers.azure.services.vm.vm_scaleset_associated_with_load_balancer.vm_scaleset_associated_with_load_balancer import (
                vm_scaleset_associated_with_load_balancer,
            )

            check = vm_scaleset_associated_with_load_balancer()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == vmss_id
            assert result[0].resource_name == "compliant-vmss"
            assert result[0].location == "eastus"
            expected_status_extended = (
                f"Scale set 'compliant-vmss' in subscription '{AZURE_SUBSCRIPTION_ID}' "
                f"is associated with load balancer backend pool(s): bepool."
            )
            assert result[0].status_extended == expected_status_extended

    def test_noncompliant_scale_set(self):
        vmss_id = str(uuid4())
        vm_scale_sets = {
            AZURE_SUBSCRIPTION_ID: {
                vmss_id: VirtualMachineScaleSet(
                    resource_id=vmss_id,
                    resource_name="noncompliant-vmss",
                    location="westeurope",
                    load_balancer_backend_pools=[],
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
            from prowler.providers.azure.services.vm.vm_scaleset_associated_with_load_balancer.vm_scaleset_associated_with_load_balancer import (
                vm_scaleset_associated_with_load_balancer,
            )

            check = vm_scaleset_associated_with_load_balancer()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == vmss_id
            assert result[0].resource_name == "noncompliant-vmss"
            assert result[0].location == "westeurope"
            expected_status_extended = (
                f"Scale set 'noncompliant-vmss' in subscription '{AZURE_SUBSCRIPTION_ID}' "
                f"is not associated with any load balancer backend pool."
            )
            assert result[0].status_extended == expected_status_extended

    def test_multiple_scale_sets(self):
        compliant_id = str(uuid4())
        noncompliant_id = str(uuid4())
        backend_pool_id = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb/backendAddressPools/bepool"
        vm_scale_sets = {
            AZURE_SUBSCRIPTION_ID: {
                compliant_id: VirtualMachineScaleSet(
                    resource_id=compliant_id,
                    resource_name="compliant-vmss",
                    location="eastus",
                    load_balancer_backend_pools=[backend_pool_id],
                ),
                noncompliant_id: VirtualMachineScaleSet(
                    resource_id=noncompliant_id,
                    resource_name="noncompliant-vmss",
                    location="westeurope",
                    load_balancer_backend_pools=[],
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
            from prowler.providers.azure.services.vm.vm_scaleset_associated_with_load_balancer.vm_scaleset_associated_with_load_balancer import (
                vm_scaleset_associated_with_load_balancer,
            )

            check = vm_scaleset_associated_with_load_balancer()
            result = check.execute()
            assert len(result) == 2
            for r in result:
                if r.resource_name == "compliant-vmss":
                    expected_status_extended = (
                        f"Scale set 'compliant-vmss' in subscription '{AZURE_SUBSCRIPTION_ID}' "
                        f"is associated with load balancer backend pool(s): bepool."
                    )
                    assert r.status == "PASS"
                    assert r.status_extended == expected_status_extended
                elif r.resource_name == "noncompliant-vmss":
                    expected_status_extended = (
                        f"Scale set 'noncompliant-vmss' in subscription '{AZURE_SUBSCRIPTION_ID}' "
                        f"is not associated with any load balancer backend pool."
                    )
                    assert r.status == "FAIL"
                    assert r.status_extended == expected_status_extended

    def test_missing_attributes(self):
        # Simulate a scale set with missing optional attributes
        vmss_id = str(uuid4())
        vm_scale_sets = {
            AZURE_SUBSCRIPTION_ID: {
                vmss_id: VirtualMachineScaleSet(
                    resource_id=vmss_id,
                    resource_name="",
                    location="",
                    load_balancer_backend_pools=[],
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
            from prowler.providers.azure.services.vm.vm_scaleset_associated_with_load_balancer.vm_scaleset_associated_with_load_balancer import (
                vm_scaleset_associated_with_load_balancer,
            )

            check = vm_scaleset_associated_with_load_balancer()
            result = check.execute()
            assert len(result) == 1
            expected_status_extended = f"Scale set '' in subscription '{AZURE_SUBSCRIPTION_ID}' is not associated with any load balancer backend pool."
            assert result[0].status == "FAIL"
            assert result[0].status_extended == expected_status_extended
