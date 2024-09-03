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
        type=validate_arguments,
        help="Use Azure CLI credentials to log in against Azure",
    )
    azure_auth_modes_group.add_argument(
        "--sp-env-auth",
        action="store_true",
        type=validate_arguments,
        help="Use Service Principal environment variables authentication to log in against Azure",
    )
    azure_auth_modes_group.add_argument(
        "--browser-auth",
        action="store_true",
        type=validate_arguments,
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
        type=validate_arguments,
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


def validate_arguments(
    az_cli_auth: bool,
    sp_env_auth: bool,
    browser_auth: bool,
    managed_identity_auth: bool,
    tenant_id: str,
):
    """
    Validates the authentication arguments for the Azure provider.

    Args:
        az_cli_auth (bool): Flag indicating whether AZ CLI authentication is enabled.
        sp_env_auth (bool): Flag indicating whether Service Principal environment authentication is enabled.
        browser_auth (bool): Flag indicating whether browser authentication is enabled.
        managed_identity_auth (bool): Flag indicating whether managed identity authentication is enabled.
        tenant_id (str): The Azure Tenant ID.

    Raises:
        AzureBrowserAuthNoTenantIDError: If browser authentication is enabled but the tenant ID is not found.
    """
    if not browser_auth and tenant_id:
        raise ArgumentTypeError(
            "Azure Tenant ID (--tenant-id) is required for browser authentication mode"
        )
    elif (
        not az_cli_auth
        and not sp_env_auth
        and not browser_auth
        and not managed_identity_auth
    ):
        raise ArgumentTypeError(
            "Azure provider requires at least one authentication method set: [--az-cli-auth | --sp-env-auth | --browser-auth | --managed-identity-auth]"
        )
    elif browser_auth and not tenant_id:
        raise ArgumentTypeError(
            "Azure Tenant ID (--tenant-id) is required for browser authentication mode"
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
