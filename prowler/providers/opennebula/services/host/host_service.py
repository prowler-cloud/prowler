from pydantic import BaseModel
from prowler.providers.opennebula.lib.service.service import OpennebulaService
from prowler.lib.logger import logger

class HostService(OpennebulaService):
    def __init__(self, provider):
        super().__init__(provider)
        self.hosts: list[Host] = []
        self.__get_hosts__()

    def __get_hosts__(self):
        try:
            hostpool = self.client.hostpool.info()
            for host in hostpool.HOST:
                online = str(host.STATE) == "2"
                healthy = online
                version = None
                if hasattr(host, "TEMPLATE") and hasattr(host.TEMPLATE, "VERSION"):
                    version = host.TEMPLATE.VERSION
                self.hosts.append(Host(
                    id=host.ID,
                    name=host.NAME,
                    state=host.STATE,
                    im_mad=host.IM_MAD,
                    vm_mad=host.VM_MAD,
                    version=version,
                    total_cpu=int(host.HOST_SHARE.MAX_CPU) if hasattr(host.HOST_SHARE, "MAX_CPU") else None,
                    used_cpu=int(host.HOST_SHARE.USED_CPU) if hasattr(host.HOST_SHARE, "USED_CPU") else None,
                    total_mem=int(host.HOST_SHARE.MAX_MEM) if hasattr(host.HOST_SHARE, "MAX_MEM") else None,
                    used_mem=int(host.HOST_SHARE.USED_MEM) if hasattr(host.HOST_SHARE, "USED_MEM") else None,
                    running_vms=int(host.HOST_SHARE.RUNNING_VMS) if hasattr(host.HOST_SHARE, "RUNNING_VMS") else None,
                    online=online,
                    healthy=healthy
                ))
        except Exception as error:
            logger.error(f"Error al obtener información de hosts: {error}")

class Host(BaseModel):
    id: str
    name: str
    state: str
    im_mad: str
    vm_mad: str
    version: str | None = None
    total_cpu: int | None = None
    used_cpu: int | None = None
    total_mem: int | None = None
    used_mem: int | None = None
    running_vms: int | None = None
    online: bool = False
    healthy: bool = True
