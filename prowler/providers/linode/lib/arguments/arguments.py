def init_parser(self):
    """Init the Linode provider CLI parser."""
    linode_parser = self.subparsers.add_parser(
        "linode", parents=[self.common_providers_parser], help="Linode Provider"
    )

    # Authentication
    # Credentials are read exclusively from the standard Linode environment
    # variable (LINODE_TOKEN) to avoid leaking secrets into shell history and
    # process listings. There are no credential CLI flags.

    # Regions
    regions_subparser = linode_parser.add_argument_group("Regions")
    regions_subparser.add_argument(
        "--region",
        "--filter-region",
        "-f",
        nargs="+",
        default=None,
        metavar="REGION",
        help="Linode region(s) to scan (e.g. eu-central us-east). Region-less "
        "resources (account, networking) are always scanned. If omitted, all "
        "regions are scanned.",
    )
