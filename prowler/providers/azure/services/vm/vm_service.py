from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from azure.mgmt.compute import ComputeManagementClient
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


class VirtualMachines(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(ComputeManagementClient, provider)
        self.virtual_machines = self._get_virtual_machines()
        self.disks = self._get_disks()

    def _get_virtual_machines(self):
        logger.info("VirtualMachines - Getting virtual machines...")
        virtual_machines = {}

        for subscription_name, client in self.clients.items():
            try:
                virtual_machines_list = client.virtual_machines.list_all()
                virtual_machines.update({subscription_name: {}})

                for vm in virtual_machines_list:
                    storage_profile = getattr(vm, "storage_profile", None)
                    os_disk = (
                        getattr(storage_profile, "os_disk", None)
                        if storage_profile
                        else None
                    )
                    data_disks = []

                    if storage_profile and getattr(storage_profile, "data_disks", []):
                        data_disks = [
                            DataDisk(
                                lun=data_disk.lun,
                                name=data_disk.name,
                                managed_disk=ManagedDiskParameters(
                                    id=(
                                        getattr(
                                            getattr(data_disk, "managed_disk", None),
                                            "id",
                                            None,
                                        )
                                        if data_disk.managed_disk
                                        else None
                                    )
                                ),
                            )
                            for data_disk in getattr(storage_profile, "data_disks", [])
                        ]

                    extensions = []
                    if getattr(vm, "resources", []):
                        extensions = [
                            VirtualMachineExtension(id=extension.id)
                            for extension in vm.resources
                            if extension
                        ]

                    virtual_machines[subscription_name].update(
                        {
                            vm.id: VirtualMachine(
                                resource_id=vm.id,
                                resource_name=vm.name,
                                storage_profile=(
                                    StorageProfile(
                                        os_disk=OSDisk(
                                            name=getattr(os_disk, "name", None),
                                            operating_system_type=getattr(
                                                os_disk, "os_type", None
                                            ),
                                            managed_disk=ManagedDiskParameters(
                                                id=getattr(
                                                    getattr(
                                                        os_disk, "managed_disk", None
                                                    ),
                                                    "id",
                                                    None,
                                                )
                                            ),
                                        ),
                                        data_disks=data_disks,
                                    )
                                    if storage_profile
                                    else None
                                ),
                                location=vm.location,
                                security_profile=getattr(vm, "security_profile", None),
                                extensions=extensions,
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return virtual_machines

    def _get_disks(self):
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
                                location=disk.location,
                                vms_attached=vms_attached,
                                encryption_type=getattr(
                                    getattr(disk, "encryption", None), "type", None
                                ),
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return disks


@dataclass
class UefiSettings:
    secure_boot_enabled: bool
    v_tpm_enabled: bool


@dataclass
class SecurityProfile:
    security_type: str
    uefi_settings: Optional[UefiSettings]


class OperatingSystemType(Enum):
    WINDOWS = "Windows"
    LINUX = "Linux"


class ManagedDiskParameters(BaseModel):
    id: str


class OSDisk(BaseModel):
    name: str
    operating_system_type: OperatingSystemType
    managed_disk: Optional[ManagedDiskParameters]


class DataDisk(BaseModel):
    lun: int
    name: str
    managed_disk: Optional[ManagedDiskParameters]


class StorageProfile(BaseModel):
    os_disk: Optional[OSDisk]
    data_disks: List[DataDisk]


class VirtualMachineExtension(BaseModel):
    id: str


class VirtualMachine(BaseModel):
    resource_id: str
    resource_name: str
    location: str
    security_profile: Optional[SecurityProfile]
    extensions: list[VirtualMachineExtension]
    storage_profile: Optional[StorageProfile] = None


class Disk(BaseModel):
    resource_id: str
    resource_name: str
    vms_attached: list[str]
    encryption_type: str
    location: str
