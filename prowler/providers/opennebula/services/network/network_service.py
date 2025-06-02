from pydantic import BaseModel
from prowler.providers.opennebula.lib.service.service import OpennebulaService
from prowler.lib.logger import logger
import ipaddress

class NetworkService(OpennebulaService):
    def __init__(self, provider):
        super().__init__(provider)
        self.vnets: list[VNet] = []
        self.__get_vnets__()

    def __get_vnets__(self):
        try:
            vnpool = self.client.vnpool.info(-2, -1, -1)  
            for vn in vnpool.VNET:
                address_ranges = [
                    {
                        "ip_start": ar.IP,
                        "size": ar.SIZE
                    } for ar in vn.AR_POOL.AR
                ]
                self.vnets.append(VNet(
                    id=vn.ID,
                    name=vn.NAME,
                    bridge=vn.BRIDGE,
                    vn_mad=vn.VN_MAD,
                    uid=vn.UID,
                    gid=vn.GID,
                    public_ips=self.__has_public_ips__(address_ranges)
                ))
        except Exception as error:
            logger.error(f"Error retrieving VNets: {error}")

    def __has_public_ips__(self, address_ranges):
        for ar in address_ranges:
            start_ip = ipaddress.ip_address(ar["ip_start"])
            for ip_offset in range(int(ar["size"])):
                ip = start_ip + ip_offset
                if not self.__is_private_ip__(ip):
                    return True
        return False

    def __is_private_ip__(self, ip):
        private_ranges = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16")
        ]
        return any(ip in private_range for private_range in private_ranges)

class VNet(BaseModel):
    id: str
    name: str
    bridge: str
    vn_mad: str
    uid: str
    gid: str
    public_ips: bool
