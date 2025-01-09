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
    gcp_auth_modes_group.add_argument(
        "--impersonate-service-account",
        nargs="?",
        metavar="SERVICE_ACCOUNT",
        help="Impersonate a Google Service Account",
    )
    # Organizations
    gcp_organization_subparser = gcp_parser.add_argument_group("Organization")
    gcp_organization_subparser.add_argument(
        "--organization-id",
        nargs="?",
        metavar="ORGANIZATION_ID",
        help="GCP Organization ID to be scanned by Prowler",
    )
    # Projects
    gcp_projects_subparser = gcp_parser.add_argument_group("Projects")
    gcp_projects_subparser.add_argument(
        "--project-id",
        "--project-ids",
        nargs="+",
        default=[],
        help="GCP Project IDs to be scanned by Prowler",
    )
    gcp_projects_subparser.add_argument(
        "--excluded-project-id",
        "--excluded-project-ids",
        nargs="+",
        default=[],
        help="Excluded GCP Project IDs to be scanned by Prowler",
    )
    gcp_projects_subparser.add_argument(
        "--list-project-id",
        "--list-project-ids",
        action="store_true",
        help="List available project IDs in Google Cloud which can be scanned by Prowler",
    )
