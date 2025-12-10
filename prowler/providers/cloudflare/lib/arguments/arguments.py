from os import environ


def init_parser(self):
    """Init the Cloudflare provider CLI parser."""
    cloudflare_parser = self.subparsers.add_parser(
        "cloudflare", parents=[self.common_providers_parser], help="Cloudflare Provider"
    )

    auth_group = cloudflare_parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "--cloudflare-api-token",
        nargs="?",
        default=None,
        metavar="CLOUDFLARE_API_TOKEN",
        help="Cloudflare API Token used for authentication (preferred)",
    )
    auth_group.add_argument(
        "--cloudflare-api-key",
        nargs="?",
        default=None,
        metavar="CLOUDFLARE_API_KEY",
        help="Cloudflare API key (legacy authentication)",
    )
    auth_group.add_argument(
        "--cloudflare-api-email",
        nargs="?",
        default=None,
        metavar="CLOUDFLARE_API_EMAIL",
        help="Email associated with the Cloudflare API key (required when using --cloudflare-api-key)",
    )

    scope_group = cloudflare_parser.add_argument_group("Scope")
    scope_group.add_argument(
        "--cloudflare-account-id",
        "--cloudflare-account",
        nargs="*",
        default=None,
        metavar="CLOUDFLARE_ACCOUNT_ID",
        help="Restrict the scan to one or more Cloudflare accounts (IDs).",
    )
    scope_group.add_argument(
        "--cloudflare-zone",
        "--cloudflare-zone-id",
        nargs="*",
        default=None,
        metavar="CLOUDFLARE_ZONE",
        help="Restrict the scan to one or more Cloudflare zones (name or ID).",
    )


def validate_arguments(arguments) -> tuple[bool, str]:
    """Validate Cloudflare provider arguments."""
    token = arguments.cloudflare_api_token or environ.get("CLOUDFLARE_API_TOKEN", "")
    api_key = arguments.cloudflare_api_key or environ.get("CLOUDFLARE_API_KEY", "")
    api_email = arguments.cloudflare_api_email or environ.get(
        "CLOUDFLARE_API_EMAIL", ""
    )

    if not token and not (api_key and api_email):
        return (
            False,
            "Cloudflare provider requires CLOUDFLARE_API_TOKEN (or --cloudflare-api-token) or the combination of CLOUDFLARE_API_KEY and CLOUDFLARE_API_EMAIL (or --cloudflare-api-key and --cloudflare-api-email).",
        )

    return (True, "")
