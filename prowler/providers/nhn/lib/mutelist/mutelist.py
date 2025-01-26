from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.check.models import Check_Report

class NHNMutelist(Mutelist):
    """
    NHN 전용 MuteList 클래스.
    Prowler가 기대하는 필드/메서드를 그대로 상속받아 사용.
    """

    def is_finding_muted(self, finding: Check_Report) -> bool:
        """
        필요한 경우, GCP나 Azure처럼 특정 조건에 따라 무시할 수도 있음.
        기본적으로 Mutelist의 is_muted(...)를 바로 호출해도 되고,
        여기서 한 번 더 NHN만의 로직을 추가해도 됨.
        """
        # finding에서 region, resource_name 등을 가져와
        # self.is_muted(...)에 전달할 수 있음
        return self.is_muted(
            # 예시:
            finding.resource_id,
            finding.check_metadata.CheckID,
            finding.location,
            finding.resource_name,
            # 태그 정보가 있으면 unroll_dict를 쓸 수도 있음
        )
