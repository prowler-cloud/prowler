def init_parser(self):
    """Init the Opennebula Provider CLI parser"""
    open_parser = self.subparsers.add_parser(
        "opennebula", parents=[self.common_providers_parser], help="Opennebula Provider"
    )
    
    # Authentication and Configuration
    open_auth_subparser = open_parser.add_argument_group(
        "Authentication and Configuration"
    )
    open_auth_subparser.add_argument(
        "--credentials-file",
        nargs="?",
        metavar="FILE_PATH",
        help="Path to the credentials file to connect with the OpenNebula API.",
        default="~/.one/one_auth",
    )

