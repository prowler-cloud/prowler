import requests
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

    def list_servers(self) -> list:
        """
        서버(인스턴스) 목록을 가져오는 메서드 (예시).
        NHN 문서: GET /v2/{tenantId}/servers
        """
        print("Listing servers...")
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
            # NHN 문서에 따라, data["servers"] 형태인지 data["serverList"] 형태인지 확인해보세요.
            return data.get("servers", [])
        except Exception as e:
            logger.error(f"Error listing servers: {e}")
            return []

    def get_server_detail(self, server_id: str) -> dict:
        """
        특정 서버 상세 정보 조회
        서버 목록 상세보기와 다름에 주의
        예: GET /v2/{tenantId}/servers/{serverId}
        """
        print(f"Getting server detail: {server_id}")
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

    # 필요하다면, 보안 그룹(방화벽) 조회, Floating IP 리스트 조회 등 메서드를 추가할 수 있습니다.
