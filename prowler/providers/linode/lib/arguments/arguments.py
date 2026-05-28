SENSITIVE_ARGUMENTS = frozenset({"--linode-token"})


def init_parser(self):
    """Init the Linode provider CLI parser."""
    linode_parser = self.subparsers.add_parser(
        "linode", parents=[self.common_providers_parser], help="Linode Provider"
    )

    auth_group = linode_parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "--linode-token",
        nargs="?",
        default=None,
        metavar="LINODE_TOKEN",
        help="Linode Personal Access Token (falls back to LINODE_TOKEN env var).",
    )
