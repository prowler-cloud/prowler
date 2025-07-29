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
        self.vm_scale_sets = self._get_vm_scale_sets()

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

                    # Collect LinuxConfiguration.disablePasswordAuthentication if available
                    linux_configuration = None
                    os_profile = getattr(vm, "os_profile", None)
                    if os_profile:
                        linux_conf = getattr(os_profile, "linux_configuration", None)
                        if linux_conf:
                            linux_configuration = LinuxConfiguration(
                                disable_password_authentication=getattr(
                                    linux_conf, "disable_password_authentication", False
                                )
                            )

                    # Convert Azure SDK SecurityProfile to custom SecurityProfile dataclass
                    azure_security_profile = getattr(vm, "security_profile", None)
                    security_profile = None
                    if azure_security_profile:
                        uefi_settings = None
                        azure_uefi_settings = getattr(
                            azure_security_profile, "uefi_settings", None
                        )
                        if azure_uefi_settings:
                            uefi_settings = UefiSettings(
                                secure_boot_enabled=getattr(
                                    azure_uefi_settings, "secure_boot_enabled", False
                                ),
                                v_tpm_enabled=getattr(
                                    azure_uefi_settings, "v_tpm_enabled", False
                                ),
                            )
                        security_profile = SecurityProfile(
                            security_type=getattr(
                                azure_security_profile, "security_type", None
                            ),
                            uefi_settings=uefi_settings,
                        )

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
                                security_profile=security_profile,
                                extensions=extensions,
                                vm_size=getattr(
                                    getattr(vm, "hardware_profile", None),
                                    "vm_size",
                                    None,
                                ),
                                image_reference=getattr(
                                    getattr(storage_profile, "image_reference", None),
                                    "id",
                                    None,
                                ),
                                linux_configuration=linux_configuration,
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

    def _get_vm_scale_sets(self) -> dict[str, dict]:
        """
        Get all needed information about VM scale sets.

        Returns:
            A nested dictionary with the following structure:
            {
                "subscription_name": {
                    "vm_scale_set_id": VirtualMachineScaleSet()
                }
            }
        """
        logger.info(
            "VirtualMachines - Getting VM scale sets and their load balancer associations..."
        )
        vm_scale_sets = {}
        for subscription_name, client in self.clients.items():
            try:
                scale_sets = client.virtual_machine_scale_sets.list_all()
                vm_scale_sets[subscription_name] = {}
                for scale_set in scale_sets:
                    backend_pools = []
                    nic_configs = []
                    virtual_machine_profile = getattr(
                        scale_set, "virtual_machine_profile", None
                    )
                    if virtual_machine_profile:
                        network_profile = getattr(
                            virtual_machine_profile, "network_profile", None
                        )
                        if network_profile:
                            nic_configs = (
                                getattr(
                                    network_profile,
                                    "network_interface_configurations",
                                    [],
                                )
                                or []
                            )
                    for nic in nic_configs:
                        ip_confs = getattr(nic, "ip_configurations", [])
                        for ipconf in ip_confs:
                            pools = getattr(
                                ipconf, "load_balancer_backend_address_pools", []
                            )
                            if pools:
                                for pool in pools:
                                    if getattr(pool, "id", None):
                                        backend_pools.append(pool.id)
                    # Get instance IDs using the private method
                    instance_ids = self._get_vmss_instance_ids(
                        subscription_name, scale_set.id
                    )
                    vm_scale_sets[subscription_name][scale_set.id] = (
                        VirtualMachineScaleSet(
                            resource_id=scale_set.id,
                            resource_name=scale_set.name,
                            location=scale_set.location,
                            load_balancer_backend_pools=backend_pools,
                            instance_ids=instance_ids,
                        )
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return vm_scale_sets

    def _get_vmss_instance_ids(
        self, subscription_name: str, scale_set_id: str
    ) -> list[str]:
        """
        Given a subscription and scale set ID, return the list of VM instance IDs in the scale set.

        Args:
            subscription_name: The name of the subscription.
            scale_set_id: The ID of the scale set.

        Returns:
            A list of VM instance IDs that compose the scale set.
        """
        logger.info(
            f"VirtualMachines - Getting VM scale set instance IDs for {scale_set_id} in {subscription_name}..."
        )
        vm_instance_ids = []
        client = self.clients.get(subscription_name, None)
        try:
            resource_id_parts = scale_set_id.split("/")
            resource_group = ""
            scale_set_name = ""
            for i, part in enumerate(resource_id_parts):
                if part.lower() == "resourcegroups" and i + 1 < len(resource_id_parts):
                    resource_group = resource_id_parts[i + 1]
                if part.lower() == "virtualmachinescalesets" and i + 1 < len(
                    resource_id_parts
                ):
                    scale_set_name = resource_id_parts[i + 1]
            if resource_group and scale_set_name:
                instances = client.virtual_machine_scale_set_vms.list(
                    resource_group, scale_set_name
                )
                vm_instance_ids = [instance.instance_id for instance in instances]
        except Exception as e:
            logger.error(
                f"Failed to list instances for scale set {scale_set_name} in {resource_group}: {e}"
            )
        return vm_instance_ids


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


class LinuxConfiguration(BaseModel):
    disable_password_authentication: bool


class VirtualMachine(BaseModel):
    resource_id: str
    resource_name: str
    location: str
    security_profile: Optional[SecurityProfile]
    extensions: list[VirtualMachineExtension]
    storage_profile: Optional[StorageProfile] = None
    vm_size: Optional[str] = None
    image_reference: Optional[str] = None
    linux_configuration: Optional[LinuxConfiguration] = None


class Disk(BaseModel):
    resource_id: str
    resource_name: str
    vms_attached: list[str]
    encryption_type: str
    location: str


class VirtualMachineScaleSet(BaseModel):
    resource_id: str
    resource_name: str
    location: str
    load_balancer_backend_pools: list[str]
    instance_ids: list[str]
