from prowler.providers.azure.services.vm.vm_service import VirtualMachines
from prowler.providers.common.provider import Provider

vm_client = VirtualMachines(Provider.get_global_provider())
