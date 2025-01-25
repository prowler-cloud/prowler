# prowler/providers/nhn/nhn_provider.py
import requests
import sys
import json
from prowler.providers.common.provider import Provider

class NhnProvider(Provider):
    def __init__(
        self,
        username: str = "",
        password: str = "",
        tenant_id: str = "",
        config_path: str = "",
        mutelist_path: str = "",
        fixer_config: dict = None,
        # 필요한 인자들을 추가할 수 있습니다.
    ):
        """
        NhnProvider 생성자.
        여기서 Prowler가 CLI 등을 통해 받아온
        username, password, tenant_id 등을 저장합니다.
        """
        # 필드 저장
        self._username = username
        self._password = password
        self._tenant_id = tenant_id

        self._token = None  # 이후 인증 토큰을 저장할 변수
        self._session = None  # 세션 객체(필요하면)
        self._audit_config = fixer_config if fixer_config else {}
        self._mutelist_path = mutelist_path
        self._config_path = config_path

        # Prowler 전체에서 "글로벌 프로바이더"로 설정할 수 있음
        Provider.set_global_provider(self)

        # 인증 세션을 설정하거나, 나중에 setup_session()에서 설정할 수 있음
        self.setup_session()

    # ----------------------------
    # 1) provider.py의 추상 메서드 구현
    # ----------------------------
    @property
    def type(self) -> str:
        """이 프로바이더의 타입을 문자열로 리턴."""
        return "nhn"

    @property
    def identity(self) -> str:
        """
        provider의 'identity'를 리턴.
        AWS라면 'account ID'가 될 수 있고,
        여기서는 'tenant_id' 또는 'username'을 반환할 수 있음음.
        """
        return self._tenant_id or "NHN Cloud Tenant"

    @property
    def session(self) -> str:
        """
        Prowler에서 'session' 정보를 어디서든 참조할 수 있도록.
        여기서는 토큰이나 세션 객체를 리턴할 수도 있음.
        """
        return self._session

    @property
    def audit_config(self) -> dict:
        """Prowler의 audit_config를 반환."""
        return self._audit_config

    def setup_session(self) -> None:
        """
        실제 NHN Cloud 인증(Keystone v2.0 등)을 통해 토큰을 받는 과정.
        """
        # 예: Keystone 인증
        try:
            if not self._username or not self._password:
                print("NHN Provider - username/password 가 설정되지 않았습니다.")
                return

            url = "https://api-identity-infrastructure.nhncloudservice.com/v2.0/tokens"
            data = {
                "auth": {
                    "tenantId": self._tenant_id,
                    "passwordCredentials": {
                        "username": self._username,
                        "password": self._password,
                    },
                }
            }
            response = requests.post(url, json=data)
            if response.status_code == 200:
                resp_data = response.json()
                self._token = resp_data["access"]["token"]["id"]
                # 필요하다면 session 객체를 구성할 수도 있음
                self._session = f"Token: {self._token}"
            else:
                print(
                    f"Failed to get token. Status: {response.status_code}. "
                    f"Body: {response.text}"
                )
        except Exception as e:
            print(f"[setup_session] Error: {e}")
            sys.exit(1)

    def print_credentials(self) -> None:
        """
        CLI에서 로깅 또는 디버그 목적으로
        현재 Provider가 사용하는 자격 증명을 표시할 수 있습니다.
        """
        print(f"NHN Provider credentials:")
        print(f"  Username: {self._username}")
        print(f"  TenantID: {self._tenant_id}")
        # 토큰은 보안상 노출 지양 - 필요하면 마스킹 처리

    def test_connection(self) -> None:
        """
        Provider에서 연결 테스트를 수행하는 경우(선택).
        예: 발급받은 토큰으로 간단한 API를 호출하여 유효성 확인.
        """
        if not self._token:
            print("No token found. Please check your username/password/tenant_id.")
            return
        # 예시: 토큰이 유효한지 확인할 수 있는 API
        # NHN Cloud의 특정 엔드포인트 호출
        # pass

    def validate_arguments(self) -> None:
        """
        provider.py에 abstractmethod로 선언된 경우, 여기서 구현.
        CLI 인자로 받은 값(username, password 등)이 유효한지 검사.
        """
        if not self._username or not self._password or not self._tenant_id:
            raise ValueError("NHN Provider requires username, password, and tenant_id.")

    def get_checks_to_execute_by_audit_resources(self) -> set:
        """
        AWS에서는 S3, EC2 등 자원에 따라 체크를 구분해 '동적 체크 목록'을 가져오지만,
        NHN에서도 리소스 유형에 따라 체크를 분기하고 싶다면 override할 수 있습니다.
        """
        return super().get_checks_to_execute_by_audit_resources()
