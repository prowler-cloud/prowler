from prowler.lib.check.models import Check, Check_Report_NHN
from prowler.providers.nhn.services.compute.compute_client import compute_client

class compute_server_public_ip(Check):
    """
    서버에 공인 IP가 붙어있는지 여부를 확인하는 체크 예시.
    """

    def execute(self):
        print("NHN Compute Server Public IP Check")
        findings = []

        servers = compute_client.list_servers()

        for srv in servers:
            srv_id = srv["id"]
            detail = compute_client.get_server_detail(srv_id)
            server_info = detail.get("server", {})
            report = Check_Report_NHN(
                metadata=self.metadata(),
                resource=server_info
            )

            # 예: 인스턴스가 public IP 가지고 있으면 FAIL (정책상 허용 X)
            # 실제로 NHN 서버 구조 상, "instanceIP": {...} 형태로 있을 수도 있음
            if self.has_public_ip(server_info):
                report.status = "FAIL"
                report.status_extended = f"Server {srv_id} has a public IP assigned."
            else:
                report.status = "PASS"
                report.status_extended = f"Server {srv_id} does not have a public IP."

            findings.append(report)

        return findings

    def has_public_ip(self, server: dict) -> bool:
        """
        OS-EXT-IPS:type == 'floating'이면 공인 IP로 판단
        """
        addresses = server.get("addresses", {})
        for _, ip_list in addresses.items():
            for ip_info in ip_list:
                if ip_info.get("OS-EXT-IPS:type") == "floating":
                    return True
        return False
