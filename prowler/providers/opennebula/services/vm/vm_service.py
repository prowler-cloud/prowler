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
            vmpool = self.client.vmpool.info(-2, -1, -1, -1)  # All VMs
            for vm in vmpool.VM:
                context = {}
                if hasattr(vm.TEMPLATE, "CONTEXT"):
                    context = vm.TEMPLATE.CONTEXT._attributes if hasattr(vm.TEMPLATE.CONTEXT, "_attributes") else {}
                self.vms.append(VM(
                    id=vm.ID,
                    name=vm.NAME,
                    uname=vm.UNAME,
                    gname=vm.GNAME,
                    state=vm.STATE,
                    context=context
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