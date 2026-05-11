def init_parser(self):
    """Init the Okta Provider CLI parser.

    The Okta provider authenticates with OAuth 2.0 (private-key JWT). The
    private key is intentionally not exposed as a CLI flag — secrets must
    be supplied via the `OKTA_PRIVATE_KEY` or `OKTA_PRIVATE_KEY_FILE`
    environment variable. Non-secret values (org URL, client ID, scopes,
    kid) are flag-configurable.
    """
    okta_parser = self.subparsers.add_parser(
        "okta", parents=[self.common_providers_parser], help="Okta Provider"
    )
    okta_auth_subparser = okta_parser.add_argument_group("Authentication")
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
