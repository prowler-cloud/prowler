from argparse import Namespace


def init_parser(self):
    """Initialize the OpenStack provider CLI parser."""
    openstack_parser = self.subparsers.add_parser(
        "openstack", parents=[self.common_providers_parser], help="OpenStack Provider"
    )

    # clouds.yaml Configuration File Authentication
    openstack_clouds_yaml_subparser = openstack_parser.add_argument_group(
        "clouds.yaml Configuration File Authentication"
    )
    openstack_clouds_yaml_subparser.add_argument(
        "--clouds-yaml-file",
        nargs="?",
        default=None,
        help="Path to clouds.yaml configuration file. If not specified, standard locations will be searched (~/.config/openstack/clouds.yaml, /etc/openstack/clouds.yaml, ./clouds.yaml)",
    )
    openstack_clouds_yaml_subparser.add_argument(
        "--clouds-yaml-cloud",
        nargs="?",
        default=None,
        help="Cloud name from clouds.yaml to use for authentication. Required when using --clouds-yaml-file or when searching for clouds.yaml in standard locations",
    )

    # Explicit Credential Authentication
    openstack_explicit_subparser = openstack_parser.add_argument_group(
        "Explicit Credential Authentication"
    )
    openstack_explicit_subparser.add_argument(
        "--os-auth-url",
        nargs="?",
        default=None,
        help="OpenStack authentication URL (Keystone endpoint). Can also be set via OS_AUTH_URL environment variable",
    )
    openstack_explicit_subparser.add_argument(
        "--os-username",
        nargs="?",
        default=None,
        help="OpenStack username for authentication. Can also be set via OS_USERNAME environment variable",
    )
    openstack_explicit_subparser.add_argument(
        "--os-password",
        nargs="?",
        default=None,
        help="OpenStack password for authentication. Can also be set via OS_PASSWORD environment variable",
    )
    openstack_explicit_subparser.add_argument(
        "--os-project-id",
        nargs="?",
        default=None,
        help="OpenStack project ID (tenant ID). Can also be set via OS_PROJECT_ID environment variable",
    )
    openstack_explicit_subparser.add_argument(
        "--os-region-name",
        nargs="?",
        default=None,
        help="OpenStack region name. Can also be set via OS_REGION_NAME environment variable",
    )
    openstack_explicit_subparser.add_argument(
        "--os-user-domain-name",
        nargs="?",
        default=None,
        help="OpenStack user domain name. Can also be set via OS_USER_DOMAIN_NAME environment variable",
    )
    openstack_explicit_subparser.add_argument(
        "--os-project-domain-name",
        nargs="?",
        default=None,
        help="OpenStack project domain name. Can also be set via OS_PROJECT_DOMAIN_NAME environment variable",
    )
    openstack_explicit_subparser.add_argument(
        "--os-identity-api-version",
        nargs="?",
        default=None,
        help="OpenStack Identity API version (2 or 3). Can also be set via OS_IDENTITY_API_VERSION environment variable",
    )


def validate_arguments(arguments: Namespace) -> tuple[bool, str]:
    """
    Validate that provider arguments are valid and can be used together.

    Enforces mutual exclusivity between clouds.yaml authentication and explicit credential parameters.

    Args:
        arguments (Namespace): The parsed arguments.

    Returns:
        tuple[bool, str]: A tuple containing a boolean indicating validity and an error message.
    """
    # Check if clouds.yaml options are used with explicit credential parameters
    clouds_yaml_in_use = arguments.clouds_yaml_file or arguments.clouds_yaml_cloud

    explicit_params_in_use = any(
        [
            arguments.os_auth_url,
            arguments.os_username,
            arguments.os_password,
            arguments.os_project_id,
            arguments.os_user_domain_name,
            arguments.os_project_domain_name,
        ]
    )

    if clouds_yaml_in_use and explicit_params_in_use:
        return (
            False,
            "Cannot use clouds.yaml options (--clouds-yaml-file, --clouds-yaml-cloud) together with explicit credential parameters (--os-auth-url, --os-username, --os-password, --os-project-id, --os-user-domain-name, --os-project-domain-name). Please use one authentication method only.",
        )

    return (True, "")
