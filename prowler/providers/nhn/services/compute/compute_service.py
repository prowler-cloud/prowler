import requests
from pydantic import BaseModel
from prowler.lib.logger import logger
from prowler.providers.nhn.nhn_provider import NhnProvider

class NHNComputeService:
    """
    NHN Compute(서버) 관련 API 호출 로직을 모아놓는 클래스.

    실제 NHN 문서를 참고해서,
    - 서버 목록 조회 (GET /v2/{tenantId}/servers)
    - 서버 상세 조회 (GET /v2/{tenantId}/servers/{serverId})
    - 방화벽(보안그룹) 조회 등
    에 맞춰 메서드를 작성하면 됩니다.
    """

    def __init__(self, provider: NhnProvider):
        """
        session: NhnProvider.session (ex: 'Bearer <token>')
        tenant_id: NhnProvider._tenant_id
        """
        self.session = provider.session
        self.tenant_id = provider._tenant_id
        # 아래 endpoint는 예시입니다. NHN 문서나 콘솔에서 확인해야 합니다.
        self.endpoint = "https://kr1-api-instance.infrastructure.cloud.toast.com"

        self.instances: list[Instance] = []
        self._get_instances()

    def _list_servers(self) -> list:
        """
        서버(인스턴스) 목록을 가져오는 메서드.
        NHN 문서: GET /v2/{tenantId}/servers
        """
        url = f"{self.endpoint}/v2/{self.tenant_id}/servers"
        headers = {
            # Keystone v2.0 인증 토큰이라면 "X-Auth-Token" 또는 "X-Auth-Token: {토큰}" 사용 가능
            # session이 "Bearer <token>" 형태라면, 'Authorization' 헤더로도 가능
            "X-Auth-Token": self.session.replace("Bearer ", ""),
            "Content-Type": "application/json",
        }
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data.get("servers", [])
        except Exception as e:
            logger.error(f"Error listing servers: {e}")
            return []

    def _get_server_detail(self, server_id: str) -> dict:
        """
        특정 서버 상세 정보 조회
        서버 목록 상세보기와 다름에 주의
        예: GET /v2/{tenantId}/servers/{serverId}
        """
        url = f"{self.endpoint}/v2/{self.tenant_id}/servers/{server_id}"
        headers = {
            "X-Auth-Token": self.session.replace("Bearer ", ""),
            "Content-Type": "application/json",
        }
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error getting server detail {server_id}: {e}")
            return {}
        
    def _check_public_ip(self, server_info: dict) -> bool:
        """
        NHN에서는 addresses에 OS-EXT-IPS:type == 'floating'이 있으면 공인 IP로 판단
        """
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