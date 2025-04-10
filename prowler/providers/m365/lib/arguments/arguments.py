def init_parser(self):
    """Init the M365 Provider CLI parser"""
    m365_parser = self.subparsers.add_parser(
        "m365",
        parents=[self.common_providers_parser],
        help="M365 Provider",
    )
    # Authentication Modes
    m365_auth_subparser = m365_parser.add_argument_group("Authentication Modes")
    m365_auth_modes_group = m365_auth_subparser.add_mutually_exclusive_group()
    m365_auth_modes_group.add_argument(
        "--az-cli-auth",
        action="store_true",
        help="Use Azure CLI authentication to log in against Microsoft 365",
    )
    m365_auth_modes_group.add_argument(
        "--env-auth",
        action="store_true",
        help="Use User and Password environment variables authentication to log in against Microsoft 365",
    )
    m365_auth_modes_group.add_argument(
        "--sp-env-auth",
        action="store_true",
        help="Use Azure Service Principal environment variables authentication to log in against Microsoft 365",
    )
    m365_auth_modes_group.add_argument(
        "--browser-auth",
        action="store_true",
        help="Use Azure interactive browser authentication to log in against Microsoft 365",
    )
    m365_parser.add_argument(
        "--tenant-id",
        nargs="?",
        default=None,
        help="Microsoft 365 Tenant ID to be used with --browser-auth option",
    )
    m365_parser.add_argument(
        "--user",
        nargs="?",
        default=None,
        help="Microsoft 365 user email",
    )
    m365_parser.add_argument(
        "--encypted-password",
        nargs="?",
        default=None,
        help="Microsoft 365 encrypted password",
    )
    # Regions
    m365_regions_subparser = m365_parser.add_argument_group("Regions")
    m365_regions_subparser.add_argument(
        "--region",
        nargs="?",
        default="M365Global",
        choices=[
            "M365Global",
            "M365GlobalChina",
            "M365USGovernment",
        ],
        help="Microsoft 365 region to be used, default is M365Global",
    )
