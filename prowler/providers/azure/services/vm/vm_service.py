from dataclasses import dataclass

from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import StorageProfile

from prowler.lib.logger import logger
from prowler.providers.azure.lib.audit_info.models import Azure_Audit_Info
from prowler.providers.azure.lib.service.service import AzureService


########################## VirtualMachines
class VirtualMachines(AzureService):
    def __init__(self, audit_info: Azure_Audit_Info):
        super().__init__(ComputeManagementClient, audit_info)
        self.virtual_machines = self.__get_virtual_machines__()
        self.disks = self.__get_disks__()

    def __get_virtual_machines__(self):
        logger.info("VirtualMachines - Getting virtual machines...")
        virtual_machines = {}

        for subscription_name, client in self.clients.items():
            try:
                virtual_machines_list = client.virtual_machines.list_all()
                virtual_machines.update({subscription_name: {}})

                for vm in virtual_machines_list:
                    virtual_machines[subscription_name].update(
                        {
                            vm.vm_id: VirtualMachine(
                                resource_id=vm.id,
                                resource_name=vm.name,
                                storage_profile=vm.storage_profile,
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return virtual_machines

    def __get_disks__(self):
        logger.info("VirtualMachines - Getting disks...")
        disks = {}

        for subscription_name, client in self.clients.items():
            try:
                disks_list = client.disks.list()
                disks.update({subscription_name: {}})

                for disk in disks_list:
                    vms_attached = []
                    if disk.managed_by:
                        vms_attached.append(disk.managed_by)
                    if disk.managed_by_extended:
                        vms_attached.extend(disk.managed_by_extended)
                    disks[subscription_name].update(
                        {
                            disk.unique_id: Disk(
                                resource_id=disk.id,
                                resource_name=disk.name,
                                vms_attached=vms_attached,
                                encryption_type=getattr(disk.encryption, "type", ""),
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return disks


@dataclass
class VirtualMachine:
    resource_id: str
    resource_name: str
    storage_profile: StorageProfile


@dataclass
class Disk:
    resource_id: str
    resource_name: str
    vms_attached: list[str]
    encryption_type: str
