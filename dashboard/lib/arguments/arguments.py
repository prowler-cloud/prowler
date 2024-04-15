def init_dashboard_parser(self):
    """Init the Dashboard CLI parser"""
    # If we don't set `help="Dashboard"` this won't be rendered
    # We don't want the dashboard to inherit from the common providers parser since it's a different component
    self.subparsers.add_parser("dashboard")
