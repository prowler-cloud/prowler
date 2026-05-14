def init_parser(self):
    """Init the Google Workspace Provider CLI parser"""
    self.subparsers.add_parser(
        "googleworkspace",
        parents=[self.common_providers_parser],
        help="Google Workspace Provider",
    )
