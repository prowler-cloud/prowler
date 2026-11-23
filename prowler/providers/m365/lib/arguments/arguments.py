import argparse


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
        "--sp-env-auth",
        action="store_true",
        help="Use Service Principal environment variables authentication to log in against Microsoft 365",
    )
    m365_auth_modes_group.add_argument(
        "--env-auth",
        dest="sp_env_auth",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    m365_auth_modes_group.add_argument(
        "--browser-auth",
        action="store_true",
        help="Use Azure interactive browser authentication to log in against Microsoft 365",
    )
    m365_auth_modes_group.add_argument(
        "--certificate-auth",
        action="store_true",
        help="Use Certificate authentication to log in against Microsoft 365",
    )
    m365_parser.add_argument(
        "--certificate-path",
        nargs="?",
        default=None,
        help="Path to the certificate file to be used with --certificate-auth option",
    )
    m365_parser.add_argument(
        "--tenant-id",
        nargs="?",
        default=None,
        help="Microsoft 365 Tenant ID to be used with --browser-auth option",
    )
    m365_parser.add_argument(
        "--init-modules",
        action="store_true",
        help="Initialize Microsoft 365 PowerShell modules",
    )
    # Regions
    m365_regions_subparser = m365_parser.add_argument_group("Regions")
    m365_regions_subparser.add_argument(
        "--region",
        nargs="?",
        default="M365Global",
        choices=[
            "M365Global",
            "M365China",
            "M365USGovernment",
            "M365Custom",
        ],
        help="Microsoft 365 region to be used, default is M365Global. Use M365Custom with the endpoint arguments below for any other cloud",
    )
    m365_regions_subparser.add_argument(
        "--m365-authority-host",
        help="Microsoft Entra authority host of the cloud, required with --region M365Custom",
    )
    m365_regions_subparser.add_argument(
        "--m365-graph-endpoint",
        help="Microsoft Graph endpoint of the cloud, required with --region M365Custom",
    )


def validate_arguments(arguments: argparse.Namespace) -> tuple[bool, str]:
    """validate_arguments returns (True, "") if the custom cloud endpoint arguments can be used with the region"""
    endpoints = {
        "--m365-authority-host": arguments.m365_authority_host,
        "--m365-graph-endpoint": arguments.m365_graph_endpoint,
    }
    if arguments.region == "M365Custom":
        missing = [flag for flag, value in endpoints.items() if not value]
        if missing:
            return (False, f"--region M365Custom requires {', '.join(missing)}")
    else:
        used = [flag for flag, value in endpoints.items() if value]
        if used:
            return (
                False,
                f"{', '.join(used)} can only be used with --region M365Custom",
            )
    return (True, "")
