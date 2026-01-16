def init_parser(self):
    """Register the OpenStack provider CLI parser."""
    description = (
        "OpenStack Provider (experimental). Authentication relies on "
        "standard Keystone v3 environment variables. "
        "Required: OS_AUTH_URL, OS_USERNAME, OS_PASSWORD, OS_REGION_NAME, "
        "and OS_PROJECT_ID. "
        "Optional: OS_USER_DOMAIN_NAME, OS_PROJECT_DOMAIN_NAME, "
        "OS_IDENTITY_API_VERSION (defaults: 'Default', 'Default', '3')."
    )
    self.subparsers.add_parser(
        "openstack",
        parents=[self.common_providers_parser],
        help="OpenStack Provider",
        description=description,
    )


def validate_arguments(_):
    """No provider-specific CLI arguments for OpenStack."""
    return (True, "")
