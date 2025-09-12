from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.vm.vm_service import (
    LinuxConfiguration,
    VirtualMachine,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_vm_linux_enforce_ssh_authentication:
    def test_no_subscriptions(self):
        vm_client = mock.MagicMock
        vm_client.virtual_machines = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_linux_enforce_ssh_authentication.vm_linux_enforce_ssh_authentication.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_linux_enforce_ssh_authentication.vm_linux_enforce_ssh_authentication import (
                vm_linux_enforce_ssh_authentication,
            )

            check = vm_linux_enforce_ssh_authentication()
            result = check.execute()
            assert len(result) == 0

    def test_empty_subscription(self):
        vm_client = mock.MagicMock
        vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {}}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_linux_enforce_ssh_authentication.vm_linux_enforce_ssh_authentication.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_linux_enforce_ssh_authentication.vm_linux_enforce_ssh_authentication import (
                vm_linux_enforce_ssh_authentication,
            )

            check = vm_linux_enforce_ssh_authentication()
            result = check.execute()
            assert len(result) == 0

    def test_linux_vm_password_auth_disabled(self):
        vm_id = str(uuid4())
        vm_client = mock.MagicMock
        vm_client.virtual_machines = {
            AZURE_SUBSCRIPTION_ID: {
                vm_id: VirtualMachine(
                    resource_id=vm_id,
                    resource_name="LinuxVM",
                    location="westeurope",
                    security_profile=None,
                    extensions=[],
                    storage_profile=None,
                    linux_configuration=LinuxConfiguration(
                        disable_password_authentication=True
                    ),
                )
            }
        }
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_linux_enforce_ssh_authentication.vm_linux_enforce_ssh_authentication.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_linux_enforce_ssh_authentication.vm_linux_enforce_ssh_authentication import (
                vm_linux_enforce_ssh_authentication,
            )

            check = vm_linux_enforce_ssh_authentication()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "LinuxVM"
            assert result[0].resource_id == vm_id
            assert "password authentication disabled" in result[0].status_extended

    def test_linux_vm_password_auth_enabled(self):
        vm_id = str(uuid4())
        vm_client = mock.MagicMock
        vm_client.virtual_machines = {
            AZURE_SUBSCRIPTION_ID: {
                vm_id: VirtualMachine(
                    resource_id=vm_id,
                    resource_name="LinuxVM",
                    location="westeurope",
                    security_profile=None,
                    extensions=[],
                    storage_profile=None,
                    linux_configuration=LinuxConfiguration(
                        disable_password_authentication=False
                    ),
                )
            }
        }
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_linux_enforce_ssh_authentication.vm_linux_enforce_ssh_authentication.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_linux_enforce_ssh_authentication.vm_linux_enforce_ssh_authentication import (
                vm_linux_enforce_ssh_authentication,
            )

            check = vm_linux_enforce_ssh_authentication()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "LinuxVM"
            assert result[0].resource_id == vm_id
            assert "password authentication enabled" in result[0].status_extended

    def test_non_linux_vm(self):
        vm_id = str(uuid4())
        vm_client = mock.MagicMock
        vm_client.virtual_machines = {
            AZURE_SUBSCRIPTION_ID: {
                vm_id: VirtualMachine(
                    resource_id=vm_id,
                    resource_name="WindowsVM",
                    location="westeurope",
                    security_profile=None,
                    extensions=[],
                    storage_profile=None,
                    linux_configuration=None,  # Not a Linux VM
                )
            }
        }
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_linux_enforce_ssh_authentication.vm_linux_enforce_ssh_authentication.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_linux_enforce_ssh_authentication.vm_linux_enforce_ssh_authentication import (
                vm_linux_enforce_ssh_authentication,
            )

            check = vm_linux_enforce_ssh_authentication()
            result = check.execute()
            assert len(result) == 0
