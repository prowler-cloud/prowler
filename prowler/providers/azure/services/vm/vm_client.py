from prowler.providers.azure.services.vm.vm_service import VirtualMachines
from prowler.providers.common.common import get_global_provider

vm_client = VirtualMachines(get_global_provider())
