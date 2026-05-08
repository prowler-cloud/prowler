"""Lovable provider CLI arguments.

Authentication relies on environment variables by default. Sensitive flags are
listed in `SENSITIVE_ARGUMENTS` so the redactor and HTML output can scrub
their values when a user passes them on the command line.
"""

# Flags whose values must be redacted in HTML output and warned about when
# passed directly. The recommended path for all of these is environment
# variables.
SENSITIVE_ARGUMENTS = frozenset(
    {
        "--lovable-api-token",
        "--supabase-access-token",
    }
)


def init_parser(self):
    """Init the Lovable provider CLI parser."""
    lovable_parser = self.subparsers.add_parser(
        "lovable",
        parents=[self.common_providers_parser],
        help="Lovable Provider",
    )

    # Authentication
    auth_group = lovable_parser.add_argument_group("Authentication Modes")
    auth_group.add_argument(
        "--lovable-api-token",
        nargs="?",
        default=None,
        metavar="LOVABLE_API_TOKEN",
        help=(
            "Lovable Cloud API token. Prefer the LOVABLE_API_TOKEN environment "
            "variable instead of passing the value on the command line."
        ),
    )
    auth_group.add_argument(
        "--lovable-workspace-id",
        nargs="?",
        default=None,
        metavar="LOVABLE_WORKSPACE_ID",
        help=(
            "Restrict the assessment to a single Lovable workspace. Falls "
            "back to the LOVABLE_WORKSPACE_ID environment variable."
        ),
    )
    auth_group.add_argument(
        "--supabase-access-token",
        nargs="?",
        default=None,
        metavar="SUPABASE_ACCESS_TOKEN",
        help=(
            "Optional Supabase Management API token used for deeper RLS / "
            "auth posture checks on Supabase-backed Lovable apps. Prefer the "
            "SUPABASE_ACCESS_TOKEN environment variable."
        ),
    )

    # Scope
    scope_group = lovable_parser.add_argument_group("Scope")
    scope_group.add_argument(
        "--project",
        "--projects",
        nargs="*",
        default=None,
        metavar="PROJECT",
        help="Filter scan to specific Lovable project IDs or slugs.",
    )
    scope_group.add_argument(
        "--published-app-url",
        nargs="*",
        default=None,
        metavar="URL",
        help=(
            "Optional explicit list of published Lovable app URLs to fetch "
            "for HTTP header / secret scan checks (e.g. when the API does "
            "not expose them)."
        ),
    )
