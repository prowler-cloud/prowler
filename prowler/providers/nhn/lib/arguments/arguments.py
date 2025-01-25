from prowler.lib.logger import logger

def init_parser(self):
    """
    --nhn-username, --nhn-password, --nhn-tenant-id 같이
    NHN 프로바이더 전용 CLI 인자들을 체크하고 세팅하는 함수.
    """
    nhn_parser = self.subparsers.add_parser(
        "nhn", parents=[self.common_providers_parser], help="NHN Provider"
    )
    nhn_parser.add_argument(
        "--nhn-username",
        required=True,
        help="NHN API Username"
    )
    nhn_parser.add_argument(
        "--nhn-password",
        required=True,
        help="NHN API Password"
    )
    nhn_parser.add_argument(
        "--nhn-tenant-id",
        required=True,
        help="NHN Tenant ID"
    )
    # 필요하면 추가 인자도 등록
