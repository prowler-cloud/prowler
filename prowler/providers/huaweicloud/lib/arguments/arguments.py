def init_parser(self):
    """Init the Huawei Cloud Provider CLI parser.

    Huawei Cloud credentials are read exclusively from environment variables
    to avoid leaking secrets on the command line:
      - HUAWEICLOUD_ACCESS_KEY_ID (or HW_ACCESS_KEY)
      - HUAWEICLOUD_SECRET_ACCESS_KEY (or HW_SECRET_KEY)
      - HUAWEICLOUD_DOMAIN_ID (or HW_DOMAIN_ID)
      - HUAWEICLOUD_SECURITY_TOKEN (optional, for temporary credentials)

    The per-region project_id is resolved automatically by the SDK, so
    multi-region scans work without any project configuration.

    The region determines the Huawei Cloud endpoint domain (.com for China and
    International, .eu for Huawei Cloud Europe). Set it with the --region flag
    or the HUAWEICLOUD_REGION (or HW_REGION) environment variable; --region
    takes precedence. Non-China accounts (International, Europe) must select a
    region they can reach, e.g. eu-west-101 for Huawei Cloud Europe.

    To assume an agency in a target account, additionally set:
      - HUAWEICLOUD_AGENCY_NAME
      - HUAWEICLOUD_ASSUME_DOMAIN_ID (or HUAWEICLOUD_ASSUME_DOMAIN_NAME)
    """
    huaweicloud_parser = self.subparsers.add_parser(
        "huaweicloud",
        parents=[self.common_providers_parser],
        help="Huawei Cloud Provider",
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
        help="Huawei Cloud region IDs to run Prowler against (e.g., eu-west-101, ap-southeast-1, cn-north-4). Overrides the HUAWEICLOUD_REGION environment variable.",
    )

    huaweicloud_parser.set_defaults(provider="huaweicloud")
