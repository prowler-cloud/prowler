from pydantic import BaseModel
from prowler.lib.logger import logger
from prowler.providers.nhn.nhn_provider import NhnProvider

class NHNComputeService:

    def __init__(self, provider: NhnProvider):
        self.session = provider.session
        self.tenant_id = provider._tenant_id
        self.endpoint = "https://kr1-api-instance.infrastructure.cloud.toast.com"

        self.instances: list[Instance] = []
        self._get_instances()

    def _list_servers(self) -> list:
        url = f"{self.endpoint}/v2/{self.tenant_id}/servers"
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data.get("servers", [])
        except Exception as e:
            logger.error(f"Error listing servers: {e}")
            return []

    def _get_server_detail(self, server_id: str) -> dict:
        url = f"{self.endpoint}/v2/{self.tenant_id}/servers/{server_id}"
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error getting server detail {server_id}: {e}")
            return {}
        
    def _check_public_ip(self, server_info: dict) -> bool:
        addresses = server_info.get("addresses", {})
        for _, ip_list in addresses.items():
            for ip_info in ip_list:
                if ip_info.get("OS-EXT-IPS:type") == "floating":
                    return True
        return False
    
    def _check_security_groups(self, server_info: dict) -> bool:
        secruity_groups = server_info.get("security_groups", [])
        sg_names = []
        for sg_info in secruity_groups:
            name = sg_info.get("name", "")
            sg_names.append(name)
            
        for name in sg_names:
            if name != "default":
                return False
        return True
    
    def _check_login_user(self, server_info: dict) -> bool:
        metadata = server_info.get("metadata", {})
        login_user = metadata.get("login_username", "")
        if login_user == "Administrator" or login_user == "root" or login_user == "admin":
            return True
        return False

    def _get_instances(self):
        server_list = self._list_servers()
        for server in server_list:
            server_id = server["id"]
            server_name = server["name"]
            detail = self._get_server_detail(server_id)
            server_info = detail.get("server", {})

            server_public_ip = self._check_public_ip(server_info)
            server_security_groups = self._check_security_groups(server_info)
            server_login_user = self._check_login_user(server_info)

            instance = Instance(
                id=server_id,
                name=server_name,
                public_ip=server_public_ip,
                security_groups=server_security_groups,
                login_user=server_login_user,
            )
            self.instances.append(instance)

class Instance(BaseModel):
    id: str
    name: str
    public_ip: bool
    security_groups: bool
    login_user: bool