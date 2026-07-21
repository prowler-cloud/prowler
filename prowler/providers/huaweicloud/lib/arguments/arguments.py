def init_parser(self):
    """Init the Huawei Cloud Provider CLI parser.

    Huawei Cloud credentials are read exclusively from environment variables
    to avoid leaking secrets on the command line:
      - HUAWEICLOUD_ACCESS_KEY_ID (or HW_ACCESS_KEY)
      - HUAWEICLOUD_SECRET_ACCESS_KEY (or HW_SECRET_KEY)
      - HUAWEICLOUD_PROJECT_ID (or HW_PROJECT_ID)
      - HUAWEICLOUD_DOMAIN_ID (or HW_DOMAIN_ID)
      - HUAWEICLOUD_SECURITY_TOKEN (optional, for temporary credentials)
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
        help="Huawei Cloud region IDs to run Prowler against (e.g., cn-north-4, cn-east-3)",
    )

    huaweicloud_parser.set_defaults(provider="huaweicloud")
