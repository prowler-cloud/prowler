from os import environ


def init_parser(self):
    """Init the Cloudflare provider CLI parser."""
    cloudflare_parser = self.subparsers.add_parser(
        "cloudflare", parents=[self.common_providers_parser], help="Cloudflare Provider"
    )

    scope_group = cloudflare_parser.add_argument_group("Scope")
    scope_group.add_argument(
        "--region",
        "--filter-region",
        "-f",
        nargs="+",
        default=None,
        metavar="ZONE",
        help="Filter scan to specific Cloudflare zones (name or ID).",
    )


def validate_arguments(arguments) -> tuple[bool, str]:
    """Validate Cloudflare provider arguments."""
    token = environ.get("CLOUDFLARE_API_TOKEN", "")
    api_key = environ.get("CLOUDFLARE_API_KEY", "")
    api_email = environ.get("CLOUDFLARE_API_EMAIL", "")

    if not token and not (api_key and api_email):
        return (
            False,
            "Cloudflare provider requires CLOUDFLARE_API_TOKEN or the combination of CLOUDFLARE_API_KEY and CLOUDFLARE_API_EMAIL environment variables.",
        )

    return (True, "")
