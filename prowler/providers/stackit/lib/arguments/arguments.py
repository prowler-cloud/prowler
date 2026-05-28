from prowler.providers.stackit.stackit_provider import StackitProvider

SENSITIVE_ARGUMENTS = frozenset({"--stackit-service-account-key"})


def init_parser(self):
    """Init the StackIT Provider CLI parser"""
    stackit_parser = self.subparsers.add_parser(
        "stackit", parents=[self.common_providers_parser], help="StackIT Provider"
    )

    # Authentication
    stackit_auth_subparser = stackit_parser.add_argument_group("Authentication")
    stackit_auth_subparser.add_argument(
        "--stackit-project-id",
        nargs="?",
        default=None,
        help="StackIT Project ID to audit (alternatively set via STACKIT_PROJECT_ID environment variable)",
    )
    stackit_auth_subparser.add_argument(
        "--stackit-service-account-key-path",
        nargs="?",
        default=None,
        help=(
            "Path to a StackIT service account key JSON file. The SDK signs the RSA "
            "challenge in the key and mints/refreshes access tokens internally for "
            "the life of the scan. Alternatively set via the "
            "STACKIT_SERVICE_ACCOUNT_KEY_PATH environment variable."
        ),
    )
    stackit_auth_subparser.add_argument(
        "--stackit-service-account-key",
        nargs="?",
        default=None,
        help=(
            "Inline content of a StackIT service account key (JSON). Useful in "
            "CI/CD where the secret comes from a secret manager and you do not "
            "want to write it to disk. Prefer the STACKIT_SERVICE_ACCOUNT_KEY "
            "environment variable over this flag to avoid leaking the key "
            "through process listings or shell history."
        ),
    )

    stackit_parser.add_argument(
        "--stackit-region",
        "-r",
        nargs="+",
        help="STACKIT region(s) to scan (default: all available regions)",
        choices=StackitProvider.get_regions(),
        default=None,
    )

    scan_unused_services_subparser = stackit_parser.add_argument_group(
        "Scan Unused Services"
    )
    scan_unused_services_subparser.add_argument(
        "--scan-unused-services",
        action="store_true",
        help="Scan unused services",
    )
