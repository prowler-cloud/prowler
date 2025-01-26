from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.cis.models import NHNCISModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutput
from prowler.lib.outputs.finding import Finding

# 1) NHNCISModel이란 pydantic 모델(혹은 dataclass)을 별도 정의할 수 있습니다.
#    Microsoft365CISModel이 Microsoft365 전용 필드를 포함했듯이,
#    NHN 클라우드 특정 필드가 있다면 아래처럼 만들 수 있음.
#    (우선은 Microsoft365CISModel과 비슷한 구조로 작성)

class NHNCIS(ComplianceOutput):
    """
    이 클래스는 NHN 클라우드 CIS 컴플라이언스 출력을 담당합니다.
    """

    def transform(
        self,
        findings: list[Finding],
        compliance: Compliance,
        compliance_name: str,
    ) -> None:
        """
        NHN CIS 포맷으로 findings를 변환해서 self._data에 추가한다.
        """
        for finding in findings:
            # finding이 어떤 CIS 요구사항(requirement)에 해당하는지 확인
            finding_requirements = finding.compliance.get(compliance_name, [])
            for requirement in compliance.Requirements:
                if requirement.Id in finding_requirements:
                    # requirement마다 attribute를 순회하면서 데이터 생성
                    for attribute in requirement.Attributes:
                        compliance_row = NHNCISModel(
                            Provider=finding.provider,
                            Description=compliance.Description,
                            # ---- 예시 필드들 ----
                            SubscriptionId=finding.account_uid,  # NHN이라면 tenant/account를 지정
                            Location=finding.region,
                            AssessmentDate=str(finding.timestamp),
                            Requirements_Id=requirement.Id,
                            Requirements_Description=requirement.Description,
                            Requirements_Attributes_Section=attribute.Section,
                            # ... 이하 Microsoft365처럼 필요한 필드들 계속 ...
                            Status=finding.status,
                            StatusExtended=finding.status_extended,
                            ResourceId=finding.resource_uid,
                            ResourceName=finding.resource_name,
                            CheckId=finding.check_id,
                            Muted=finding.muted,
                        )
                        self._data.append(compliance_row)

        # 2) MANUAL 요구사항 처리
        for requirement in compliance.Requirements:
            if not requirement.Checks:  # 체크가 없는 요구사항은 수동 검사
                for attribute in requirement.Attributes:
                    compliance_row = NHNCISModel(
                        Provider=compliance.Provider.lower(),
                        Description=compliance.Description,
                        SubscriptionId="",
                        Location="",
                        AssessmentDate=str(finding.timestamp) if findings else "",
                        Requirements_Id=requirement.Id,
                        Requirements_Description=requirement.Description,
                        Requirements_Attributes_Section=attribute.Section,
                        # ... 이하 생략, 위와 동일 ...
                        Status="MANUAL",
                        StatusExtended="Manual check",
                        ResourceId="manual_check",
                        ResourceName="Manual check",
                        CheckId="manual",
                        Muted=False,
                    )
                    self._data.append(compliance_row)
