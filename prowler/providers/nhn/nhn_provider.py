import sys
import requests
from typing import Optional

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider
from prowler.providers.nhn.models import NHNIdentityInfo, NHNOutputOptions
from prowler.providers.nhn.lib.mutelist.mutelist import NHNMutelist

class NhnProvider(Provider):
    """
    NhnProvider는 NHN 클라우드용 Prowler Provider 클래스입니다.

    - 인증 세션(토큰 발급)
    - identity (tenant_id, username 등)
    - mutelist, audit_config 등 설정 로드
    - print_credentials, test_connection 등 유틸 메서드
    """

    _type:str = "nhn"
    
    def __init__(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        tenant_id: Optional[str] = None,
        config_path: Optional[str] = None,
        fixer_config: Optional[dict] = None,
        mutelist_path: Optional[str] = None,
        mutelist_content: Optional[dict] = None,
        # 필요한 인자들을 추가할 수 있습니다.
    ):
        """
        NhnProvider 생성자.

        Args:
            - username: NHN Cloud 계정 ID
            - password: NHN Cloud 계정 비밀번호
            - tenant_id: NHN Cloud Tenant ID
            - config_path: Prowler config 파일 경로
            - fixer_config: Fixer 관련 설정 (선택)
            - mutelist_path: Mutelist 파일 경로
            - mutelist_content: Mutelist 내용을 담은 dict
        """
        logger.info("Initializing NhnProvider...")

        # 1) 인자 값 저장
        self._username = username or ""
        self._password = password or ""
        self._tenant_id = tenant_id or ""

        # 2) audit_config, fixer_config, mutelist
        self._fixer_config = fixer_config if fixer_config else {}
        if not config_path:
            config_path = default_config_file_path
        self._audit_config = load_and_validate_config_file(self._type, config_path)

        if mutelist_content:
            # NHN 전용 mutelist 클래스를 만들었다면 여기서 불러서 생성
            # self._mutelist = NHNMutelist(mutelist_content=mutelist_content)
            self._mutelist = NHNMutelist(mutelist_content=mutelist_content)
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self._type)
            self._mutelist = NHNMutelist(mutelist_path=mutelist_path)
            # self._mutelist = {}  # 예시

        # 3) 세션/토큰 초기화
        self._token = None
        self._session = None
        self.setup_session()

        # 4) identity를 객체로 관리 (NHNIdentityInfo)
        #    - GCP나 Azure 예시처럼 self._identity = GCPIdentityInfo(...)
        #    - NHNIdentityInfo가 pydantic.BaseModel을 상속받았다고 가정
        self._identity = NHNIdentityInfo(
            tenant_id=self._tenant_id,
            username=self._username,
            # 필요하다면 token 필드도 저장
        )

        # 5) Prowler에서 "글로벌 프로바이더"로 등록
        Provider.set_global_provider(self)

    # ---------- #
    # Properties #
    # ---------- #
    @property
    def type(self) -> str:
        """프로바이더 타입: 'nhn'"""
        return self._type

    @property
    def identity(self) -> str:
        """
        Prowler에서 "identity" 정보를 참조할 때 사용.
        예: self.identity.tenant_id, self.identity.username 등
        """
        return self._identity

    @property
    def session(self) -> str:
        """
        'session'은 AWS, Azure, GCP 등에서는 boto3나 Azure Credential 객체가 들어감.
        NHN에서는 토큰 또는 세션 오브젝트를 반환할 수 있음.
        여기서는 단순히 토큰 문자열을 세션처럼 쓰겠다고 가정.
        """
        return self._session

    @property
    def audit_config(self) -> dict:
        """Prowler의 audit_config를 반환."""
        return self._audit_config
    
    @property
    def fixer_config(self) -> dict:
        return self._fixer_config

    @property
    def mutelist(self) -> dict:
        """
        Prowler가 provider.mutelist를 참조할 때,
        NHNMutelist 객체를 반환해야 함.
        """
        return self._mutelist
    
    # ------------------ #
    # Provider Overrides #
    # ------------------ #
    def validate_arguments(self) -> None:
        """
        Prowler의 provider.py에서는 이 메서드를 통해
        CLI 인자가 유효한지 (필수값 누락 등) 검사할 수 있음.
        """
        if not self._username or not self._password or not self._tenant_id:
            raise ValueError("NHN Provider requires username, password, and tenant_id.")
        
    def print_credentials(self) -> None:
        """
        Prowler가 시작할 때, 현재 Provider 자격 정보(계정, Tenant ID 등)를 출력.
        """
        report_lines = [
            f"NHN Provider credentials:",
            f"  Username: {self._username}",
            f"  TenantID: {self._tenant_id}",
        ]
        # 실제 토큰은 보안상 노출 자제
        # if self._token:
        #     report_lines.append(f"  Token(Truncated): {self._token[:10]}...")
        print_boxes(report_lines, "NHN Provider")

    def setup_session(self) -> None:
        """
        실제 NHN Cloud 인증(Keystone 등) 로직을 구현.
        예: Keystone v2.0 API를 호출해 토큰 발급
        """
        if not self._username or not self._password:
            logger.warning("NHN Provider - username/password not set.")
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
        # https://docs.nhncloud.com/ko/Compute/Compute/ko/identity-api/ 여기서 응답보고 넣기
        try:
            response = requests.post(url, json=data, timeout=10)
            if response.status_code == 200:
                resp_json = response.json()
                # Keystone 토큰
                self._token = resp_json["access"]["token"]["id"]
                # session에 토큰을 넣거나, requests.Session 객체를 만들어 Authorization 헤더 설정 가능
                self._session = f"Bearer {self._token}"
                logger.info(f"NHN token acquired successfully.")
            else:
                logger.error(
                    f"Failed to get token. Status: {response.status_code}, Body: {response.text}"
                )
        except Exception as e:
            logger.critical(f"[setup_session] Error: {e}")
            sys.exit(1)

    def test_connection(self) -> None:
        """
        Provider에서 연결 테스트를 수행하는 경우(선택).
        예: 발급받은 토큰으로 간단한 API를 호출하여 유효성 확인.
        """
        if not self._token:
            print("No token found. Please check your username/password/tenant_id.")
            return
        
        # 예시: 토큰으로 호출 가능한 간단한 API
        # url = "https://some-nhn-api/v1/something"
        # headers = {"X-Auth-Token": self._token}
        # try:
        #     r = requests.get(url, headers=headers, timeout=10)
        #     if r.status_code == 200:
        #         logger.info("Test connection successful!")
        #     else:
        #         logger.error(f"Test connection failed: {r.status_code} - {r.text}")
        # except Exception as e:
        #     logger.error(f"Test connection error: {e}")

    def get_checks_to_execute_by_audit_resources(self) -> set:
        """
        AWS에서는 S3, EC2 등 자원에 따라 체크를 구분해 '동적 체크 목록'을 가져오지만,
        NHN에서도 리소스 유형에 따라 체크를 분기하고 싶다면 override할 수 있습니다.
        """
        return super().get_checks_to_execute_by_audit_resources()
