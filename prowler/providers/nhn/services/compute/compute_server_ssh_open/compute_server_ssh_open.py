from prowler.lib.check.models import Check, Check_Report_NHN
from prowler.providers.nhn.nhn_provider import NhnProvider
from prowler.providers.common.provider import Provider
from prowler.providers.nhn.services.compute.compute_service import NHNComputeService

class compute_server_ssh_open(Check):
    """
    예시: 서버 목록 중, SSH(22번 포트)가 공인 IP로 열려 있는지 검사해서 FAIL/PASS를 판단.
    """

    def execute(self):
        findings = []

        # 1) NHN Provider 가져오기
        # provider: NhnProvider = self.provider
        provider = Provider.get_global_provider()
        # 2) NHNComputeService 생성
        compute_service = NHNComputeService(
            session=provider.session, 
            tenant_id=provider._tenant_id
        )

        # 3) 서버 목록 가져오기
        servers = compute_service.list_servers()

        # 4) 각 서버에 대해 SSH 포트가 오픈됐는지(예시) 점검
        #    실제로는 보안 그룹 또는 네트워크 인터페이스 정보를 확인해야 합니다.
        for srv in servers:
            srv_id = srv["id"]
            detail = compute_service.get_server_detail(srv_id)
            server_info = detail.get("server", {})
            report = Check_Report_NHN(
                metadata=self.metadata(),
                resource=server_info
            )
            # resource_name, resource_id, location 등은 Check_Report_NHN __init__에서 자동 맵핑

            if self.is_ssh_open_to_public(srv):
                report.status = "FAIL"
                report.status_extended = (
                    f"Server {srv_id} has SSH open to the world."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Server {srv_id} has no public SSH open."
                )

            findings.append(report)

        return findings

    def is_ssh_open_to_public(self, srv_obj: dict) -> bool:
        """
        실제 SSH(22포트)가 퍼블릭 IP로 오픈되어 있는지 판별 (예시).
        - 보안 그룹/Firewall 규칙 또는 IP 바인딩 상태를 파악해야 함.
        - 여기서는 가상 코드.
        """
        # 예: srv_obj.get("security_groups")에서 0.0.0.0/0 + port=22 가 있으면 True -> 귀찮... https://docs.nhncloud.com/ko/Network/Security%20Groups/ko/public-api/#_21 
        # 여기서 보안 그룹 id 가져가서 확인해야함
        # 아래는 가짜 로직
        sg_list = srv_obj.get("security_groups", [])
        for sg in sg_list:
            rules = sg.get("rules", [])
            for rule in rules:
                if rule.get("port") == 22 and rule.get("cidr") == "0.0.0.0/0":
                    return True
        return False
