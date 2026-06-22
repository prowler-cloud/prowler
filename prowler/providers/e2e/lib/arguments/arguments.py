import os

SENSITIVE_ARGUMENTS = frozenset({"--e2e-api-key", "--e2e-auth-token"})


def init_parser(self):
    """Init the E2E Cloud Provider CLI parser."""
    e2e_parser = self.subparsers.add_parser(
        "e2e",
        parents=[self.common_providers_parser],
        help="E2E Cloud Provider",
    )

    auth_group = e2e_parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "--e2e-api-key",
        nargs="?",
        default=None,
        metavar="E2E_API_KEY",
        help="E2E Cloud API key. Use E2E_API_KEY env var instead of passing directly.",
    )
    auth_group.add_argument(
        "--e2e-auth-token",
        nargs="?",
        default=None,
        metavar="E2E_AUTH_TOKEN",
        help="E2E Cloud auth token. Use E2E_AUTH_TOKEN env var instead of passing directly.",
    )
    auth_group.add_argument(
        "--e2e-project-id",
        nargs="?",
        default=None,
        metavar="E2E_PROJECT_ID",
        help="E2E Cloud project ID. Use E2E_PROJECT_ID env var instead of passing directly.",
    )

    scope_group = e2e_parser.add_argument_group("Scope")
    scope_group.add_argument(
        "--e2e-location",
        "--e2e-locations",
        nargs="*",
        default=None,
        metavar="LOCATION",
        help="E2E Cloud region(s) to scan (e.g. Delhi Chennai). Defaults to E2E_LOCATION or Delhi.",
    )


def validate_arguments(arguments) -> tuple[bool, str]:
    """Validate E2E Cloud provider CLI arguments."""
    api_key = arguments.e2e_api_key or os.getenv("E2E_API_KEY")
    auth_token = arguments.e2e_auth_token or os.getenv("E2E_AUTH_TOKEN")
    project_id = arguments.e2e_project_id or os.getenv("E2E_PROJECT_ID")

    if not api_key:
        return False, "E2E Cloud provider requires an API key (E2E_API_KEY)."
    if not auth_token:
        return False, "E2E Cloud provider requires an auth token (E2E_AUTH_TOKEN)."
    if not project_id:
        return False, "E2E Cloud provider requires a project ID (E2E_PROJECT_ID)."

    try:
        int(project_id)
    except (TypeError, ValueError):
        return False, "E2E Cloud project ID must be an integer."

    return True, ""
