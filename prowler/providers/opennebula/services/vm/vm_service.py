from pydantic import BaseModel
from prowler.providers.opennebula.lib.service.service import OpennebulaService
from prowler.lib.logger import logger

class VMService(OpennebulaService):
    def __init__(self, provider):
        super().__init__(provider)
        self.vms: list[VM] = []
        self.__get_vms__()

    def __get_vms__(self):
        try:
            # Primero, obtenemos la lista de IDs de todas las VMs
            vmpool = self.client.vmpool.info(-2, -1, -1, -1)  # All VMs
            vm_ids = [vm.ID for vm in vmpool.VM]
            for vm_id in vm_ids:
                vm = self.client.vm.info(vm_id)
                template_raw = getattr(vm.TEMPLATE, "_attributes", vm.TEMPLATE)
                context = {}
                if isinstance(template_raw, dict):
                    context = template_raw.get("CONTEXT", {})
                elif hasattr(template_raw, "CONTEXT"):
                    context_attr = getattr(template_raw, "CONTEXT")
                    context = getattr(context_attr, "_attributes", context_attr) or {}

                self.vms.append(VM(
                    id=vm.ID,
                    name=vm.NAME,
                    uname=vm.UNAME,
                    gname=vm.GNAME,
                    state=vm.STATE,
                    context=context,
                    template_raw=template_raw
                ))

        except Exception as error:
            logger.error(f"Error al obtener máquinas virtuales: {error}")

class VM(BaseModel):
    id: str
    name: str
    uname: str
    gname: str
    state: str
    context: dict
    template_raw: dict
