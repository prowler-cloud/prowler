def init_parser(self):
    """Init the Okta Provider CLI parser.

    The Okta provider authenticates with OAuth 2.0 (private-key JWT). The
    private key is intentionally not exposed as a CLI flag — secrets must
    be supplied via the `OKTA_PRIVATE_KEY` or `OKTA_PRIVATE_KEY_FILE`
    environment variable. Non-secret values (org URL, client ID, scopes)
    are flag-configurable.
    """
    okta_parser = self.subparsers.add_parser(
        "okta", parents=[self.common_providers_parser], help="Okta Provider"
    )
    okta_auth_subparser = okta_parser.add_argument_group("Authentication")
    okta_auth_subparser.add_argument(
        "--okta-org-domain",
        nargs="?",
        help=(
            "Okta organization domain (e.g. acme.okta.com). Must be an "
            "Okta-managed domain (.okta.com / .oktapreview.com / "
            ".okta-emea.com / .okta-gov.com / .okta.mil / "
            ".okta-miltest.com / .trex-govcloud.com), without scheme or path."
        ),
        default=None,
        metavar="OKTA_ORG_DOMAIN",
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
        nargs="+",
        help=(
            "OAuth scopes to request, space-separated "
            "(e.g. okta.policies.read okta.brands.read okta.apps.read "
            "okta.logStreams.read okta.idps.read). "
            "Defaults to the read scopes required by the bundled checks."
        ),
        default=None,
        metavar="OKTA_SCOPES",
    )
    okta_rate_limit_subparser = okta_parser.add_argument_group("Rate limiting")
    okta_rate_limit_subparser.add_argument(
        "--okta-retries-max-attempts",
        type=int,
        default=None,
        help=(
            "Maximum number of retries on Okta API rate limiting (HTTP 429). "
            "Overrides the config.yaml value (okta_max_retries). Default: 5."
        ),
        metavar="OKTA_RETRIES_MAX_ATTEMPTS",
    )
    okta_rate_limit_subparser.add_argument(
        "--okta-requests-per-second",
        type=float,
        default=None,
        help=(
            "Maximum aggregate Okta API requests per second. Throttles requests "
            "to stay under Okta's rate limits. Overrides the config.yaml value "
            "(okta_requests_per_second); set to 0 to disable. Default: 4."
        ),
        metavar="OKTA_REQUESTS_PER_SECOND",
    )
