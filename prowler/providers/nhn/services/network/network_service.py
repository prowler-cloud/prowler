from pydantic import BaseModel
from prowler.lib.logger import logger
from prowler.providers.nhn.nhn_provider import NhnProvider

class Subnet(BaseModel):
    name: str
    external_router: bool
    enable_dhcp: bool
    
class Network(BaseModel):
    id: str
    name: str
    empty_routingtables: bool
    subnets: list[Subnet]

class NHNNetworkService:
    def __init__(self, provider: NhnProvider):
        self.session = provider.session
        self.tenant_id = provider._tenant_id
        self.endpoint = "https://kr1-api-network-infrastructure.nhncloudservice.com"
        self.networks: list[Network] = []
        self._get_networks()

    def _list_vpcs(self) -> list:
        url = f"{self.endpoint}/v2.0/vpcs"
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data.get("vpcs", [])
        except Exception as e:
            logger.error(f"Error listing vpcs: {e}")
            return []
        
    def _get_vpc_detail(self, vpc_id: str) -> dict:
        url = f"{self.endpoint}/v2.0/vpcs/{vpc_id}"
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error getting vpc detail {vpc_id}: {e}")
            return {}
           
    def _check_has_empty_routingtables(self, vpc_info: dict) -> bool:
        routingtables = vpc_info.get("routingtables", [])
        return not routingtables
    
    def _check_subnet_has_external_router(self, subnet: dict) -> bool:
        return subnet.get("router:external", True)
    
    def _check_subnet_enable_dhcp(self, subnet: dict) -> bool:
        return subnet.get("enable_dhcp", True)
    
    def _get_networks(self):
        vpc_list = self._list_vpcs()
        for vpc in vpc_list:
            vpc_id = vpc["id"]
            vpc_name = vpc["name"]
            detail = self._get_vpc_detail(vpc_id)
            vpc_info = detail.get("vpc", {})
            vpc_empty_routingtables = self._check_has_empty_routingtables(vpc_info)

            network = Network(
                id=vpc_id,
                name=vpc_name,
                empty_routingtables=vpc_empty_routingtables,
                subnets=[]
            )
            self._get_subnets(vpc_info, network)
            self.networks.append(network)
        
    def _get_subnets(self, vpc_info: dict, network: Network):
        subnet_list = vpc_info.get("subnets", [])
        # ret_subnet_list = []
        for subnet in subnet_list:
            subnet_name = subnet["name"]
            subnet_external_router = self._check_subnet_has_external_router(subnet)
            subnet_enable_dhcp = self._check_subnet_enable_dhcp(subnet)
            subnet_instance = Subnet(
                name=subnet_name,
                external_router=subnet_external_router,
                enable_dhcp=subnet_enable_dhcp
            )
            network.subnets.append(subnet_instance)
