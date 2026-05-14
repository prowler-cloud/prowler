def init_parser(self):
    """Init the Alibaba Cloud Provider CLI parser"""
    alibabacloud_parser = self.subparsers.add_parser(
        "alibabacloud",
        parents=[self.common_providers_parser],
        help="Alibaba Cloud Provider",
    )

    # Authentication Methods
    alibabacloud_auth_subparser = alibabacloud_parser.add_argument_group(
        "Authentication Modes"
    )
    alibabacloud_auth_subparser.add_argument(
        "--role-arn",
        nargs="?",
        default=None,
        help="ARN of the RAM role to assume (e.g., acs:ram::123456789012:role/ProwlerAuditRole). Requires access keys to be set via environment variables (ALIBABA_CLOUD_ACCESS_KEY_ID and ALIBABA_CLOUD_ACCESS_KEY_SECRET). The provider will automatically obtain and refresh STS tokens. Can also use ALIBABA_CLOUD_ROLE_ARN environment variable",
    )
    alibabacloud_auth_subparser.add_argument(
        "--role-session-name",
        nargs="?",
        default=None,
        help="Session name when assuming the RAM role. Defaults to ProwlerAssessmentSession. Can also use ALIBABA_CLOUD_ROLE_SESSION_NAME environment variable",
    )
    alibabacloud_auth_subparser.add_argument(
        "--ecs-ram-role",
        nargs="?",
        default=None,
        help="Name of the RAM role attached to an ECS instance. When specified, credentials are obtained from the ECS instance metadata service. Can also use ALIBABA_CLOUD_ECS_METADATA environment variable",
    )
    alibabacloud_auth_subparser.add_argument(
        "--oidc-role-arn",
        nargs="?",
        default=None,
        help="ARN of the RAM role for OIDC authentication. Requires OIDC provider ARN and token file to be set via environment variables (ALIBABA_CLOUD_OIDC_PROVIDER_ARN and ALIBABA_CLOUD_OIDC_TOKEN_FILE). Can also use ALIBABA_CLOUD_ROLE_ARN environment variable",
    )
    alibabacloud_auth_subparser.add_argument(
        "--credentials-uri",
        nargs="?",
        default=None,
        help="URI to retrieve credentials from an external service. The URI must return credentials in the required JSON format. Can also use ALIBABA_CLOUD_CREDENTIALS_URI environment variable",
    )

    # Alibaba Cloud Regions
    alibabacloud_regions_subparser = alibabacloud_parser.add_argument_group(
        "Alibaba Cloud Regions"
    )
    alibabacloud_regions_subparser.add_argument(
        "--region",
        "--filter-region",
        "-f",
        nargs="+",
        dest="regions",
        help="Alibaba Cloud region IDs to run Prowler against (e.g., cn-hangzhou, cn-shanghai)",
    )

    # Set the provider
    alibabacloud_parser.set_defaults(provider="alibabacloud")
