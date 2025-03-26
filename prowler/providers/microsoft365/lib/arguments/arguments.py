def init_parser(self):
    """Init the Microsoft365 Provider CLI parser"""
    microsoft365_parser = self.subparsers.add_parser(
        "microsoft365",
        parents=[self.common_providers_parser],
        help="Microsoft365 Provider",
    )
    # Authentication Modes
    microsoft365_auth_subparser = microsoft365_parser.add_argument_group(
        "Authentication Modes"
    )
    microsoft365_auth_modes_group = (
        microsoft365_auth_subparser.add_mutually_exclusive_group()
    )
    microsoft365_auth_modes_group.add_argument(
        "--az-cli-auth",
        action="store_true",
        help="Use Azure CLI authentication to log in against Microsoft365",
    )
    microsoft365_auth_modes_group.add_argument(
        "--sp-env-auth",
        action="store_true",
        help="Use Azure Service Principal environment variables authentication to log in against Microsoft365",
    )
    microsoft365_auth_modes_group.add_argument(
        "--browser-auth",
        action="store_true",
        help="Use Azure interactive browser authentication to log in against Microsoft365",
    )
    microsoft365_parser.add_argument(
        "--tenant-id",
        nargs="?",
        default=None,
        help="Microsoft365 Tenant ID to be used with --browser-auth option",
    )
    # Regions
    microsoft365_regions_subparser = microsoft365_parser.add_argument_group("Regions")
    microsoft365_regions_subparser.add_argument(
        "--region",
        nargs="?",
        default="Microsoft365Global",
        choices=[
            "Microsoft365Global",
            "Microsoft365GlobalChina",
            "Microsoft365USGovernment",
        ],
        help="Microsoft365 region to be used, default is Microsoft365Global",
    )
    # PowerShell
    microsoft365_credentials_subparser = microsoft365_parser.add_argument_group(
        "PowerShell"
    )
    microsoft365_credentials_subparser.add_argument(
        "--credentials-env-auth",
        action="store_true",
        help="Use User and Password environment variables authentication to log in against Microsoft365",
    )
