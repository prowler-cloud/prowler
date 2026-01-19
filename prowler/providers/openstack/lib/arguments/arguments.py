def init_parser(self):
    """Initialize the OpenStack provider CLI parser."""
    self.subparsers.add_parser(
        "openstack", parents=[self.common_providers_parser], help="OpenStack Provider"
    )


def validate_arguments(_):
    """No provider-specific CLI arguments for OpenStack."""
    return (True, "")
