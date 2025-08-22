SCANNERS_CHOICES = [
    "vuln",
    "misconfig",
    "secret",
    "license",
]


def init_parser(self):
    """Init the IAC Provider CLI parser"""
    iac_parser = self.subparsers.add_parser(
        "iac", parents=[self.common_providers_parser], help="IaC Provider"
    )

    # Scan Path
    iac_scan_subparser = iac_parser.add_argument_group("Scan Path")
    iac_scan_subparser.add_argument(
        "--scan-path",
        "-P",
        dest="scan_path",
        default=".",
        help="Path to the folder containing your infrastructure-as-code files. Default: current directory. Mutually exclusive with --scan-repository-url.",
    )

    iac_scan_subparser.add_argument(
        "--scan-repository-url",
        "-R",
        dest="scan_repository_url",
        default=None,
        help="URL to the repository containing your infrastructure-as-code files. Mutually exclusive with --scan-path.",
    )

    iac_scan_subparser.add_argument(
        "--scanners",
        "--scanner",
        dest="scanners",
        nargs="+",
        default=["vuln", "misconfig", "secret"],
        choices=SCANNERS_CHOICES,
        help="Comma-separated list of scanners to scan. Default: vuln, misconfig, secret",
    )
    iac_scan_subparser.add_argument(
        "--exclude-path",
        dest="exclude_path",
        nargs="+",
        default=[],
        help="Comma-separated list of paths to exclude from the scan. Default: none",
    )

    iac_scan_subparser.add_argument(
        "--github-username",
        dest="github_username",
        nargs="?",
        default=None,
        help="GitHub username for authenticated repository cloning (used with --personal-access-token). If not provided, will use GITHUB_USERNAME env var.",
    )
    iac_scan_subparser.add_argument(
        "--personal-access-token",
        dest="personal_access_token",
        nargs="?",
        default=None,
        help="GitHub personal access token for authenticated repository cloning (used with --github-username). If not provided, will use GITHUB_PERSONAL_ACCESS_TOKEN env var.",
    )
    iac_scan_subparser.add_argument(
        "--oauth-app-token",
        dest="oauth_app_token",
        nargs="?",
        default=None,
        help="GitHub OAuth app token for authenticated repository cloning. If not provided, will use GITHUB_OAUTH_APP_TOKEN env var.",
    )


def validate_arguments(arguments):
    scan_path = getattr(arguments, "scan_path", None)
    scan_repository_url = getattr(arguments, "scan_repository_url", None)
    if scan_path and scan_repository_url:
        # If scan_path is set to default ("."), allow scan_repository_url
        if scan_path != ".":
            return (
                False,
                "--scan-path (-P) and --scan-repository-url (-R) are mutually exclusive. Please specify only one.",
            )
    return (True, "")
