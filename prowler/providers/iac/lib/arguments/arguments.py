def init_parser(self):
    """Init the IAC Provider CLI parser"""
    iac_parser = self.subparsers.add_parser(
        "iac", parents=[self.common_providers_parser], help="IaC Provider"
    )

    # Scan Path
    iac_scan_subparser = iac_parser.add_argument_group("Scan Path")
    iac_scan_subparser.add_argument(
        "--scan-path",
        "-P",
        dest="scan_path",
        default=".",
        help="Path to the folder containing your infrastructure-as-code files. Default: current directory",
    )

    iac_scan_subparser.add_argument(
        "--scan-repository-url",
        "-R",
        dest="scan_repository_url",
        default=None,
        help="URL to the repository containing your infrastructure-as-code files.",
    )
