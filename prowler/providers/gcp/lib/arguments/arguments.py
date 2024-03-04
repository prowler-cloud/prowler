def init_parser(self):
    """Init the GCP Provider CLI parser"""
    gcp_parser = self.subparsers.add_parser(
        "gcp", parents=[self.common_providers_parser], help="GCP Provider"
    )
    # Authentication Modes
    gcp_auth_subparser = gcp_parser.add_argument_group("Authentication Modes")
    gcp_auth_modes_group = gcp_auth_subparser.add_mutually_exclusive_group()
    gcp_auth_modes_group.add_argument(
        "--credentials-file",
        nargs="?",
        metavar="FILE_PATH",
        help="Authenticate using a Google Service Account Application Credentials JSON file",
    )
    # Subscriptions
    gcp_subscriptions_subparser = gcp_parser.add_argument_group("Projects")
    gcp_subscriptions_subparser.add_argument(
        "--project-ids",
        nargs="+",
        default=[],
        help="GCP Project IDs to be scanned by Prowler",
    )

    # 3rd Party Integrations
    gcp_3rd_party_subparser = gcp_parser.add_argument_group("3rd Party Integrations")
    gcp_3rd_party_subparser.add_argument(
        "-N",
        "--shodan",
        nargs="?",
        default=None,
        help="Shodan API key used by check compute_public_address_shodan.",
    )
