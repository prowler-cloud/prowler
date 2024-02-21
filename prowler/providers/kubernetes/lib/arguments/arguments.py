def init_parser(self):
    """Init the Kubernetes Provider CLI parser"""
    k8s_parser = self.subparsers.add_parser(
        "kubernetes", parents=[self.common_providers_parser], help="Kubernetes Provider"
    )
    # Authentication and Configuration
    k8s_auth_subparser = k8s_parser.add_argument_group(
        "Authentication and Configuration"
    )
    k8s_auth_subparser.add_argument(
        "--kubeconfig-file",
        nargs="?",
        metavar="FILE_PATH",
        help="Path to the kubeconfig file to use for CLI requests. Not necessary for in-cluster execution.",
    )
    k8s_auth_subparser.add_argument(
        "--context",
        nargs="?",
        metavar="CONTEXT_NAME",
        help="The name of the kubeconfig context to use. By default, current_context from config file will be used.",
    )
    k8s_auth_subparser.add_argument(
        "--namespace",
        nargs="?",
        metavar="NAMESPACE",
        help="The namespace to use for the Kubernetes resources. By default, Prowler will scan all namespaces available.",
    )
