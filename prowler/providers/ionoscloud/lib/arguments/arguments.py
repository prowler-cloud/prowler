def init_parser(self):
    """Init the IONOS Cloud Provider CLI parser"""
    ionoscloud_parser = self.subparsers.add_parser(
        "ionoscloud",
        parents=[self.common_providers_parser],
        help="IONOS Cloud Provider",
    )

    # Authentication
    ionoscloud_auth = ionoscloud_parser.add_argument_group("Authentication Modes")
    ionoscloud_auth.add_argument(
        "--username",
        nargs="?",
        default=None,
        help="IONOS Cloud username (email). Can also be set via IONOS_USERNAME environment variable.",
    )
    ionoscloud_auth.add_argument(
        "--password",
        nargs="?",
        default=None,
        help="IONOS Cloud password. Can also be set via IONOS_PASSWORD environment variable.",
    )
    ionoscloud_auth.add_argument(
        "--token",
        nargs="?",
        default=None,
        help="IONOS Cloud API token. Can also be set via IONOS_TOKEN environment variable.",
    )

    # Location filtering
    ionoscloud_locations = ionoscloud_parser.add_argument_group("IONOS Cloud Locations")
    ionoscloud_locations.add_argument(
        "--location",
        "--filter-location",
        "-f",
        nargs="+",
        dest="locations",
        help="IONOS Cloud locations to run Prowler against (e.g., de/fra, us/las). "
        "If not specified, all locations are audited.",
    )

    ionoscloud_parser.set_defaults(provider="ionoscloud")
