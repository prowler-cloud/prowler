from argparse import ArgumentTypeError


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
        "--app-env-auth",
        action="store_true",
        help="Use application environment variables authentication to log in against Microsoft 365",
    )
    # Regions
    microsoft365_regions_subparser = microsoft365_parser.add_argument_group("Regions")
    microsoft365_regions_subparser.add_argument(
        "--microsoft365-region",
        nargs="?",
        default="AzureCloud",
        type=validate_microsoft365_region,
        help="microsoft365 region from `az cloud list --output table`, by default AzureCloud",
    )


def validate_microsoft365_region(region):
    """validate_microsoft365_region validates if the region passed as argument is valid"""
    regions_allowed = [
        "AzureChinaCloud",
        "AzureUSGovernment",
        "AzureCloud",
    ]
    if region not in regions_allowed:
        raise ArgumentTypeError(
            f"Region {region} not allowed, allowed regions are {' '.join(regions_allowed)}"
        )
    return region
