def init_parser(self):
    """Init the NHN Provider CLI parser"""
    nhn_parser = self.subparsers.add_parser(
        "nhn", parents=[self.common_providers_parser], help="NHN Provider"
    )

    # Authentication
    nhn_auth_subparser = nhn_parser.add_argument_group("Authentication")
    nhn_auth_subparser.add_argument(
        "--nhn-username", nargs="?", default=None, help="NHN API Username"
    )
    nhn_auth_subparser.add_argument(
        "--nhn-password", nargs="?", default=None, help="NHN API Password"
    )
    nhn_auth_subparser.add_argument(
        "--nhn-tenant-id", nargs="?", default=None, help="NHN Tenant ID"
    )
