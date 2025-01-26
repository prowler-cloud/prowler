from pydantic import BaseModel
from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions

class NHNIdentityInfo(BaseModel):
    identity_id: str = ""
    identity_type: str = ""
    tenant_id: str = ""
    tenant_domain: str = ""
    # NHN 클라우드마다 유저/프로젝트/테넌트 구조가 다르다면 필요한 필드 추가
    # e.g. project_no, region, etc.

class NHNRegionConfig(BaseModel):
    name: str = ""
    # NHN 클라우드마다 리전 정보가 다르다면 필요한 필드 추가
    # e.g. endpoint, region_code, etc.

class NHNOutputOptions(ProviderOutputOptions):
    def __init__(self, arguments, bulk_checks_metadata, identity: NHNIdentityInfo):
        """
        NHN에서만 필요한 출력 옵션(예: 파일명 생성 규칙 등)을 구현.
        """
        super().__init__(arguments, bulk_checks_metadata)

        # --output-filename이 없으면, 기본 규칙으로 파일명을 생성
        if not getattr(arguments, "output_filename", None):
            # 만약 identity.tenant_id 가 있으면 포함(ex: prowler-output-nhn-tenant_id-20210901)
            if identity.tenant_id:
                self.output_filename = (
                    f"prowler-output-nhn-{identity.tenant_id}-{output_file_timestamp}"
                )
            # 없으면 기본 파일명 생성(ex: prowler-output-nhn-20210901)
            else:
                self.output_filename = (
                    f"prowler-output-nhn-{output_file_timestamp}"
                )
        # --output-filename이 있으면 명시적으로 설정된 경우, 그대로 사용
        else:
            self.output_filename = arguments.output_filename
