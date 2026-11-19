from argparse import ArgumentTypeError, Namespace

from prowler.providers.azure.lib.regions.regions import AZURE_CUSTOM_CLOUD


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
        help="Use Azure CLI credentials to log in against Azure",
    )
    azure_auth_modes_group.add_argument(
        "--sp-env-auth",
        action="store_true",
        help="Use Service Principal environment variables authentication to log in against Azure",
    )
    azure_auth_modes_group.add_argument(
        "--browser-auth",
        action="store_true",
        help="Use browser authentication to log in against Azure, --tenant-id is required for this option",
    )
    azure_auth_modes_group.add_argument(
        "--managed-identity-auth",
        action="store_true",
        help="Use managed identity authentication to log in against Azure ",
    )
    # Subscriptions
    azure_subscriptions_subparser = azure_parser.add_argument_group("Subscriptions")
    azure_subscriptions_subparser.add_argument(
        "--subscription-id",
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
        help="Azure region from `az cloud list --output table`, by default AzureCloud. Use AzureCustom with the endpoint arguments below for any other cloud",
    )
    azure_regions_subparser.add_argument(
        "--azure-authority-host",
        help="Microsoft Entra authority host of the cloud, required with --azure-region AzureCustom",
    )
    azure_regions_subparser.add_argument(
        "--azure-resource-manager-endpoint",
        help="Azure Resource Manager endpoint of the cloud, required with --azure-region AzureCustom",
    )
    azure_regions_subparser.add_argument(
        "--azure-graph-endpoint",
        help="Microsoft Graph endpoint of the cloud, required with --azure-region AzureCustom",
    )
    azure_regions_subparser.add_argument(
        "--azure-logs-endpoint",
        help="Log Analytics endpoint of the cloud, optional with --azure-region AzureCustom. Without it, checks that query Log Analytics are not evaluated",
    )
    # Resource Groups
    azure_rg_subparser = azure_parser.add_argument_group("Resource Groups")
    azure_rg_subparser.add_argument(
        "--azure-resource-group",
        "--azure-resource-groups",
        nargs="+",
        default=[],
        dest="resource_groups",
        help="Azure Resource Group names to scope the scan to specific groups.",
    )


def validate_azure_region(region):
    """validate_azure_region validates if the region passed as argument is valid"""
    regions_allowed = [
        "AzureChinaCloud",
        "AzureUSGovernment",
        "AzureCloud",
        AZURE_CUSTOM_CLOUD,
    ]
    if region not in regions_allowed:
        raise ArgumentTypeError(
            f"Region {region} not allowed, allowed regions are {' '.join(regions_allowed)}"
        )
    return region


def validate_arguments(arguments: Namespace) -> tuple[bool, str]:
    """validate_arguments returns (True, "") if the custom cloud endpoint arguments can be used with the region"""
    endpoints = {
        "--azure-authority-host": arguments.azure_authority_host,
        "--azure-resource-manager-endpoint": arguments.azure_resource_manager_endpoint,
        "--azure-graph-endpoint": arguments.azure_graph_endpoint,
    }
    if arguments.azure_region == AZURE_CUSTOM_CLOUD:
        missing = [flag for flag, value in endpoints.items() if not value]
        if missing:
            return (
                False,
                f"--azure-region AzureCustom requires {', '.join(missing)}",
            )
    else:
        endpoints["--azure-logs-endpoint"] = arguments.azure_logs_endpoint
        used = [flag for flag, value in endpoints.items() if value]
        if used:
            return (
                False,
                f"{', '.join(used)} can only be used with --azure-region AzureCustom",
            )
    return (True, "")
