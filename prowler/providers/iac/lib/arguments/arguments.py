FRAMEWORK_CHOICES = [
    "ansible",
    "argo_workflows",
    "arm",
    "azure_pipelines",
    "bicep",
    "bitbucket",
    "bitbucket_pipelines",
    "cdk",
    "circleci_pipelines",
    "cloudformation",
    "dockerfile",
    "github",
    "github_actions",
    "gitlab",
    "gitlab_ci",
    "helm",
    "json_doc",
    "kubernetes",
    "kustomize",
    "openapi",
    "policies_3d",
    "sast",
    "sca_image",
    "sca_package_2",
    "secrets",
    "serverless",
    "terraform",
    "terraform_json",
    "yaml_doc",
]


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
        "--frameworks",
        "-f",
        "--framework",
        dest="frameworks",
        nargs="+",
        default=["all"],
        choices=FRAMEWORK_CHOICES,
        help="Comma-separated list of frameworks to scan. Default: all",
    )
    iac_scan_subparser.add_argument(
        "--exclude-path",
        dest="exclude_path",
        nargs="+",
        default=[],
        help="Comma-separated list of paths to exclude from the scan. Default: none",
    )
