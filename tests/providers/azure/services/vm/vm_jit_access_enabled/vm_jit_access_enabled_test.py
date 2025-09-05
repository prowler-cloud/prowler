from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.defender.defender_service import JITPolicy
from prowler.providers.azure.services.vm.vm_service import VirtualMachine
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_vm_jit_access_enabled:
    def test_no_subscriptions(self):
        vm_client = mock.MagicMock()
        vm_client.virtual_machines = {}
        defender_client = mock.MagicMock()
        defender_client.jit_policies = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_jit_access_enabled.vm_jit_access_enabled.vm_client",
                new=vm_client,
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_jit_access_enabled.vm_jit_access_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_jit_access_enabled.vm_jit_access_enabled import (
                vm_jit_access_enabled,
            )

            check = vm_jit_access_enabled()
            result = check.execute()
            assert result == []

    def test_no_vms(self):
        vm_client = mock.MagicMock()
        vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {}}
        defender_client = mock.MagicMock()
        defender_client.jit_policies = {AZURE_SUBSCRIPTION_ID: {}}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_jit_access_enabled.vm_jit_access_enabled.vm_client",
                new=vm_client,
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_jit_access_enabled.vm_jit_access_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_jit_access_enabled.vm_jit_access_enabled import (
                vm_jit_access_enabled,
            )

            check = vm_jit_access_enabled()
            result = check.execute()
            assert result == []

    def test_vm_with_jit_enabled(self):
        vm_id = str(uuid4())
        vm_name = "TestVM"
        vm_location = "eastus"
        vm = VirtualMachine(
            resource_id=vm_id,
            resource_name=vm_name,
            location=vm_location,
            security_profile=None,
            extensions=[],
            storage_profile=None,
        )
        vm_client = mock.MagicMock()
        vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {vm_id: vm}}
        defender_client = mock.MagicMock()
        jit_policy = JITPolicy(
            id="policy1",
            name="JITPolicy1",
            location="eastus",
            vm_ids={vm_id},
        )
        defender_client.jit_policies = {
            AZURE_SUBSCRIPTION_ID: {jit_policy.id: jit_policy}
        }
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_jit_access_enabled.vm_jit_access_enabled.vm_client",
                new=vm_client,
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_jit_access_enabled.vm_jit_access_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_jit_access_enabled.vm_jit_access_enabled import (
                vm_jit_access_enabled,
            )

            check = vm_jit_access_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_id == vm_id
            assert result[0].resource_name == vm_name
            assert "has JIT (Just-in-Time) access enabled" in result[0].status_extended

    def test_vm_with_jit_disabled(self):
        vm_id = str(uuid4())
        vm_name = "TestVM"
        vm_location = "eastus"
        vm = VirtualMachine(
            resource_id=vm_id,
            resource_name=vm_name,
            location=vm_location,
            security_profile=None,
            extensions=[],
            storage_profile=None,
        )
        vm_client = mock.MagicMock()
        vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {vm_id: vm}}
        defender_client = mock.MagicMock()
        # JIT policy does not include this VM
        jit_policy = JITPolicy(
            id="policy1",
            name="JITPolicy1",
            location="eastus",
            vm_ids={"some-other-id"},
        )
        defender_client.jit_policies = {
            AZURE_SUBSCRIPTION_ID: {jit_policy.id: jit_policy}
        }
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_jit_access_enabled.vm_jit_access_enabled.vm_client",
                new=vm_client,
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_jit_access_enabled.vm_jit_access_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_jit_access_enabled.vm_jit_access_enabled import (
                vm_jit_access_enabled,
            )

            check = vm_jit_access_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_id == vm_id
            assert result[0].resource_name == vm_name
            assert (
                "does not have JIT (Just-in-Time) access enabled"
                in result[0].status_extended
            )

    def test_vm_id_case_insensitivity(self):
        vm_id = str(uuid4())
        vm_name = "TestVM"
        vm_location = "eastus"
        upper_vm_id = vm_id.upper()
        vm = VirtualMachine(
            resource_id=upper_vm_id,
            resource_name=vm_name,
            location=vm_location,
            security_profile=None,
            extensions=[],
            storage_profile=None,
        )
        vm_client = mock.MagicMock()
        vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {upper_vm_id: vm}}
        defender_client = mock.MagicMock()
        jit_policy = JITPolicy(
            id="policy1",
            name="JITPolicy1",
            location="eastus",
            vm_ids={vm_id.lower()},
        )
        defender_client.jit_policies = {
            AZURE_SUBSCRIPTION_ID: {jit_policy.id: jit_policy}
        }
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_jit_access_enabled.vm_jit_access_enabled.vm_client",
                new=vm_client,
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_jit_access_enabled.vm_jit_access_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_jit_access_enabled.vm_jit_access_enabled import (
                vm_jit_access_enabled,
            )

            check = vm_jit_access_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == upper_vm_id
            assert "has JIT (Just-in-Time) access enabled" in result[0].status_extended

    def test_multiple_vms_and_policies(self):
        vm_id_1 = str(uuid4())
        vm_id_2 = str(uuid4())
        vm1 = VirtualMachine(
            resource_id=vm_id_1,
            resource_name="VM1",
            location="eastus",
            security_profile=None,
            extensions=[],
            storage_profile=None,
        )
        vm2 = VirtualMachine(
            resource_id=vm_id_2,
            resource_name="VM2",
            location="eastus",
            security_profile=None,
            extensions=[],
            storage_profile=None,
        )
        vm_client = mock.MagicMock()
        vm_client.virtual_machines = {
            AZURE_SUBSCRIPTION_ID: {vm_id_1: vm1, vm_id_2: vm2}
        }
        defender_client = mock.MagicMock()
        jit_policy_1 = JITPolicy(
            id="policy1",
            name="JITPolicy1",
            location="eastus",
            vm_ids={vm_id_1},
        )
        jit_policy_2 = JITPolicy(
            id="policy2",
            name="JITPolicy2",
            location="eastus",
            vm_ids=set(),
        )
        defender_client.jit_policies = {
            AZURE_SUBSCRIPTION_ID: {
                jit_policy_1.id: jit_policy_1,
                jit_policy_2.id: jit_policy_2,
            }
        }
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_jit_access_enabled.vm_jit_access_enabled.vm_client",
                new=vm_client,
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_jit_access_enabled.vm_jit_access_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_jit_access_enabled.vm_jit_access_enabled import (
                vm_jit_access_enabled,
            )

            check = vm_jit_access_enabled()
            result = check.execute()
            assert len(result) == 2
            for r in result:
                if r.resource_id == vm_id_1:
                    assert r.status == "PASS"
                elif r.resource_id == vm_id_2:
                    assert r.status == "FAIL"
