"""Pipeline Provider Arguments."""


def init_parser(self):
    """Init the Pipeline Provider CLI parser."""
    pipeline_parser = self.subparsers.add_parser(
        "pipeline",
        parents=[self.common_providers_parser],
        help="CI/CD Pipeline Security Provider (using Poutine)",
    )
    # Add common arguments
    pipeline_parser.add_argument(
        "--scan-path",
        nargs="?",
        default=".",
        help="Path to local directory containing pipeline files (default: current directory)",
    )
    pipeline_parser.add_argument(
        "--repository-url",
        help="URL of remote repository to scan (e.g., https://github.com/org/repo)",
    )
    pipeline_parser.add_argument(
        "--organization",
        help="Organization name to scan all repositories",
    )
    pipeline_parser.add_argument(
        "--platform",
        choices=["github", "gitlab", "azure", "tekton"],
        default="github",
        help="CI/CD platform type (default: github)",
    )
    pipeline_parser.add_argument(
        "--token",
        help="Authentication token for the CI/CD platform",
    )
    pipeline_parser.add_argument(
        "--exclude-paths",
        nargs="+",
        default=[],
        help="Paths to exclude from scanning",
    )


def validate_arguments(arguments):
    """Validate Pipeline Provider arguments."""

    # Check for conflicting scan targets
    targets = [
        bool(arguments.scan_path and arguments.scan_path != "."),
        bool(arguments.repository_url),
        bool(arguments.organization),
    ]

    if sum(targets) > 1:
        return (
            False,
            "Only one of --scan-path, --repository-url, or --organization can be specified",
        )

    # Warn if token not provided for remote scanning
    if (arguments.repository_url or arguments.organization) and not arguments.token:
        print(
            "\nWarning: Remote scanning without --token may have limited functionality. "
            "Some security checks require authentication to detect.\n"
        )

    # Validate platform-specific requirements
    if arguments.platform == "gitlab" and arguments.organization:
        return (
            False,
            "Organization scanning is not supported for GitLab. Use --repository-url instead.",
        )

    return True, ""
