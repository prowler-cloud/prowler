from prowler.providers.azure.lib.audit_info.audit_info import azure_audit_info
from prowler.providers.azure.services.vm.vm_service import VirtualMachines

vm_client = VirtualMachines(azure_audit_info)
