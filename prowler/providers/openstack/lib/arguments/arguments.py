def init_parser(self):
    """Register the OpenStack provider CLI parser."""
    description = (
        "OpenStack Provider (experimental). Authentication relies solely on the "
        "standard Keystone v3 environment variables. "
        "Ensure OS_AUTH_URL, OS_USERNAME, OS_PASSWORD, OS_PROJECT_ID or OS_TENANT_ID, "
        "OS_REGION_NAME, OS_USER_DOMAIN_NAME, and OS_PROJECT_DOMAIN_NAME are exported "
        "before running Prowler."
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
