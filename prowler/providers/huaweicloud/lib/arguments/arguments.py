SENSITIVE_ARGUMENTS = frozenset({"--secret-access-key", "--security-token"})


def init_parser(self):
    """Init the Huawei Cloud Provider CLI parser"""
    huaweicloud_parser = self.subparsers.add_parser(
        "huaweicloud",
        parents=[self.common_providers_parser],
        help="Huawei Cloud Provider",
    )

    huaweicloud_auth_subparser = huaweicloud_parser.add_argument_group(
        "Authentication Modes"
    )
    huaweicloud_auth_subparser.add_argument(
        "--access-key-id",
        nargs="?",
        default=None,
        help="Huawei Cloud Access Key ID. Can also use HUAWEICLOUD_ACCESS_KEY_ID or HW_ACCESS_KEY environment variable",
    )
    huaweicloud_auth_subparser.add_argument(
        "--secret-access-key",
        nargs="?",
        default=None,
        metavar="HUAWEICLOUD_SECRET_ACCESS_KEY",
        help="Huawei Cloud Secret Access Key. Use the HUAWEICLOUD_SECRET_ACCESS_KEY or HW_SECRET_KEY environment variable instead of passing it directly",
    )
    huaweicloud_auth_subparser.add_argument(
        "--project-id",
        nargs="?",
        default=None,
        help="Huawei Cloud Project ID (required for regional services). Can also use HUAWEICLOUD_PROJECT_ID or HW_PROJECT_ID environment variable",
    )
    huaweicloud_auth_subparser.add_argument(
        "--domain-id",
        nargs="?",
        default=None,
        help="Huawei Cloud Domain ID. Can also use HUAWEICLOUD_DOMAIN_ID or HW_DOMAIN_ID environment variable",
    )
    huaweicloud_auth_subparser.add_argument(
        "--security-token",
        nargs="?",
        default=None,
        metavar="HUAWEICLOUD_SECURITY_TOKEN",
        help="Security Token for temporary credentials. Use the HUAWEICLOUD_SECURITY_TOKEN environment variable instead of passing it directly",
    )
    huaweicloud_auth_subparser.add_argument(
        "--agency-name",
        nargs="?",
        default=None,
        help="Name of the agency to assume for cross-account access",
    )
    huaweicloud_auth_subparser.add_argument(
        "--delegation-domain-id",
        nargs="?",
        default=None,
        help="Domain ID of the delegating account for agency assumption",
    )

    huaweicloud_regions_subparser = huaweicloud_parser.add_argument_group(
        "Huawei Cloud Regions"
    )
    huaweicloud_regions_subparser.add_argument(
        "--region",
        "--filter-region",
        "-f",
        nargs="+",
        dest="regions",
        help="Huawei Cloud region IDs to run Prowler against (e.g., cn-north-4, cn-east-3)",
    )

    huaweicloud_parser.set_defaults(provider="huaweicloud")
