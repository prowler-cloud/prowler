def init_parser(self):
    """Init the IAC Provider CLI parser"""
    iac_parser = self.subparsers.add_parser(
        "iac", parents=[self.common_providers_parser], help="IaC Provider"
    )
    iac_parser.add_argument(
        "--scan-path",
        "-P",
        dest="scan_path",
        default=".",
        help="Path to the folder containing your infrastructure-as-code files. Default: current directory",
    )
