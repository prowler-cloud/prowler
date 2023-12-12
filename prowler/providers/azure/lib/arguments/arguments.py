from argparse import ArgumentTypeError


def init_parser(self):
    """Init the Azure Provider CLI parser"""
    azure_parser = self.subparsers.add_parser(
        "azure", parents=[self.common_providers_parser], help="Azure Provider"
    )
    # Authentication Modes
    azure_auth_subparser = azure_parser.add_argument_group("Authentication Modes")
    azure_auth_modes_group = azure_auth_subparser.add_mutually_exclusive_group()
    azure_auth_modes_group.add_argument(
        "--az-cli-auth",
        action="store_true",
        help="Use Azure cli credentials to log in against azure",
    )
    azure_auth_modes_group.add_argument(
        "--sp-env-auth",
        action="store_true",
        help="Use service principal env variables authentication to log in against azure",
    )
    azure_auth_modes_group.add_argument(
        "--browser-auth",
        action="store_true",
        help="Use browser authentication to log in against Azure, --tenant-id is required for this option",
    )
    azure_auth_modes_group.add_argument(
        "--managed-identity-auth",
        action="store_true",
        help="Use managed identity authentication to log in against azure ",
    )
    # Subscriptions
    azure_subscriptions_subparser = azure_parser.add_argument_group("Subscriptions")
    azure_subscriptions_subparser.add_argument(
        "--subscription-ids",
        nargs="+",
        default=[],
        help="Azure Subscription IDs to be scanned by Prowler",
    )
    azure_parser.add_argument(
        "--tenant-id",
        nargs="?",
        default=None,
        help="Azure Tenant ID to be used with --browser-auth option",
    )
    # Regions
    azure_regions_subparser = azure_parser.add_argument_group("Regions")
    azure_regions_subparser.add_argument(
        "--azure-region",
        nargs="?",
        default="AzureCloud",
        type=validate_azure_region,
        help="Azure region from `az cloud list --output table`, by default AzureCloud",
    )


def validate_azure_region(region):
    """validate_azure_region validates if the region passed as argument is valid"""
    regions_allowed = [
        "AzureChinaCloud",
        "AzureUSGovernment",
        "AzureGermanCloud",
        "AzureCloud",
    ]
    if region not in regions_allowed:
        raise ArgumentTypeError(
            f"Region {region} not allowed, allowed regions are {' '.join(regions_allowed)}"
        )
    return region
