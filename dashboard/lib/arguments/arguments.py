def init_dashboard_parser(self):
    """Init the Dashboard CLI parser"""
    # If we don't set `help="Dashboard"` this won't be rendered
    self.subparsers.add_parser("dashboard", parents=[self.common_providers_parser])
