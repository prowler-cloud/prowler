SENSITIVE_ARGUMENTS = frozenset({"--okta-private-key", "--okta-private-key-file"})


def init_parser(self):
    """Init the Okta Provider CLI parser"""
    okta_parser = self.subparsers.add_parser(
        "okta", parents=[self.common_providers_parser], help="Okta Provider"
    )
    okta_auth_subparser = okta_parser.add_argument_group("Authentication")
    # OAuth 2.0 service app (private-key JWT) — the only supported flow in v1
    okta_auth_subparser.add_argument(
        "--okta-org-url",
        nargs="?",
        help="Okta organization URL (e.g. https://acme.okta.com)",
        default=None,
        metavar="OKTA_ORG_URL",
    )
    okta_auth_subparser.add_argument(
        "--okta-client-id",
        nargs="?",
        help="Okta service app Client ID for OAuth 2.0 (private-key JWT)",
        default=None,
        metavar="OKTA_CLIENT_ID",
    )
    okta_auth_subparser.add_argument(
        "--okta-private-key",
        nargs="?",
        help=(
            "Okta service app private key as raw content (PEM or JWK). "
            "Use OKTA_PRIVATE_KEY env var instead of passing directly. "
            "Takes precedence over --okta-private-key-file when both are set."
        ),
        default=None,
        metavar="OKTA_PRIVATE_KEY",
    )
    okta_auth_subparser.add_argument(
        "--okta-private-key-file",
        nargs="?",
        help=(
            "Path to a file containing the Okta service app private key "
            "(PEM or JWK). Use OKTA_PRIVATE_KEY_FILE env var instead of "
            "passing directly."
        ),
        default=None,
        metavar="OKTA_PRIVATE_KEY_FILE",
    )
    okta_auth_subparser.add_argument(
        "--okta-scopes",
        nargs="?",
        help=(
            "Comma-separated list of OAuth scopes. Defaults to the read "
            "scopes required by the bundled checks."
        ),
        default=None,
        metavar="OKTA_SCOPES",
    )
    okta_auth_subparser.add_argument(
        "--okta-kid",
        nargs="?",
        help="Optional JWK Key ID, only required if not embedded in the JWK",
        default=None,
        metavar="OKTA_KID",
    )
