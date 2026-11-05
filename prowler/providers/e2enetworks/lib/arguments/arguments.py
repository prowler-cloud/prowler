import os

SENSITIVE_ARGUMENTS = frozenset({"--e2e-networks-api-key", "--e2e-networks-auth-token"})


def init_parser(self):
    """Init the E2E Networks Provider CLI parser."""
    e2enetworks_parser = self.subparsers.add_parser(
        "e2enetworks",
        parents=[self.common_providers_parser],
        help="E2E Networks Provider",
    )

    auth_group = e2enetworks_parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "--e2e-networks-api-key",
        nargs="?",
        default=None,
        metavar="E2E_NETWORKS_API_KEY",
        help="E2E Networks API key. Use E2E_NETWORKS_API_KEY env var instead of passing directly.",
    )
    auth_group.add_argument(
        "--e2e-networks-auth-token",
        nargs="?",
        default=None,
        metavar="E2E_NETWORKS_AUTH_TOKEN",
        help="E2E Networks auth token. Use E2E_NETWORKS_AUTH_TOKEN env var instead of passing directly.",
    )
    auth_group.add_argument(
        "--e2e-networks-project-id",
        nargs="?",
        default=None,
        metavar="E2E_NETWORKS_PROJECT_ID",
        help="E2E Networks project ID. Use E2E_NETWORKS_PROJECT_ID env var instead of passing directly.",
    )

    regions_subparser = e2enetworks_parser.add_argument_group("Regions")
    regions_subparser.add_argument(
        "--region",
        "--filter-region",
        "-f",
        nargs="+",
        default=None,
        metavar="REGION",
        help="E2E Networks region(s) to scan (e.g. Delhi Chennai). If omitted, "
        "uses E2E_NETWORKS_REGION or scans all regions (Delhi, Chennai).",
    )


def validate_arguments(arguments) -> tuple[bool, str]:
    """Validate E2E Networks provider CLI arguments.

    Only argument consistency is checked here so that listing operations such as
    ``--list-checks`` and ``--list-services`` run without credentials. Credential
    presence (API key, auth token and project ID) is enforced later at provider
    initialization, when an actual scan is performed.
    """
    project_id = arguments.e2e_networks_project_id or os.getenv(
        "E2E_NETWORKS_PROJECT_ID"
    )

    if project_id is not None:
        try:
            int(project_id)
        except (TypeError, ValueError):
            return False, "E2E Networks project ID must be an integer."

    return True, ""
