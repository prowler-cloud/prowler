def init_parser(self):
    nhn_parser = self.subparsers.add_parser(
        "nhn", parents=[self.common_providers_parser], help="NHN Provider"
    )
    nhn_parser.add_argument("--nhn-username", required=True, help="NHN API Username")
    nhn_parser.add_argument("--nhn-password", required=True, help="NHN API Password")
    nhn_parser.add_argument("--nhn-tenant-id", required=True, help="NHN Tenant ID")
