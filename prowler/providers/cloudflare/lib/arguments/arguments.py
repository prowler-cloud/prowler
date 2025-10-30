def init_parser(self):
    """Init the Cloudflare Provider CLI parser"""
    cloudflare_parser = self.subparsers.add_parser(
        "cloudflare",
        parents=[self.common_providers_parser],
        help="Cloudflare Provider",
    )
    cloudflare_auth_subparser = cloudflare_parser.add_argument_group(
        "Authentication Modes"
    )
    # Authentication Modes
    cloudflare_auth_subparser.add_argument(
        "--api-token",
        nargs="?",
        help="Cloudflare API Token for authentication",
        default=None,
        metavar="CLOUDFLARE_API_TOKEN",
    )

    cloudflare_auth_subparser.add_argument(
        "--api-key",
        nargs="?",
        help="Cloudflare API Key for authentication (requires --api-email)",
        default=None,
        metavar="CLOUDFLARE_API_KEY",
    )

    cloudflare_auth_subparser.add_argument(
        "--api-email",
        nargs="?",
        help="Cloudflare API Email for authentication (used with --api-key)",
        default=None,
        metavar="CLOUDFLARE_API_EMAIL",
    )

    cloudflare_scoping_subparser = cloudflare_parser.add_argument_group("Scan Scoping")
    cloudflare_scoping_subparser.add_argument(
        "--account-id",
        "--account-ids",
        nargs="*",
        help="Cloudflare Account ID(s) to scan",
        default=None,
        metavar="ACCOUNT_ID",
    )

    cloudflare_scoping_subparser.add_argument(
        "--zone-id",
        "--zone-ids",
        nargs="*",
        help="Cloudflare Zone ID(s) to scan",
        default=None,
        metavar="ZONE_ID",
    )


def validate_arguments(arguments):
    """
    Validate Cloudflare provider arguments.

    Returns:
        tuple: (is_valid, error_message)
    """
    # If API key is provided, email must also be provided
    if arguments.api_key and not arguments.api_email:
        return (
            False,
            "Cloudflare API Key requires API Email. Please provide --api-email",
        )

    if arguments.api_email and not arguments.api_key:
        return (
            False,
            "Cloudflare API Email requires API Key. Please provide --api-key",
        )

    return (True, "")
