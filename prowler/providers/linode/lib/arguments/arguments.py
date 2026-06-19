def init_parser(self):
    """Init the Linode provider CLI parser."""
    self.subparsers.add_parser(
        "linode", parents=[self.common_providers_parser], help="Linode Provider"
    )

    # Authentication
    # Credentials are read exclusively from the standard Linode environment
    # variable (LINODE_TOKEN) to avoid leaking secrets into shell history and
    # process listings. There are no credential CLI flags.
