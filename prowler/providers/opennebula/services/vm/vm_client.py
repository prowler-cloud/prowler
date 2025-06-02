from prowler.providers.opennebula.services.vm.vm_service import VMService
from prowler.providers.common.provider import Provider

vm_client = VMService(Provider.get_global_provider())
