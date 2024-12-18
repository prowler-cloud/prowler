def init_parser(self):
    """Init the Github Provider CLI parser"""
    github_parser = self.subparsers.add_parser(
        "github", parents=[self.common_providers_parser], help="GitHub Provider"
    )
    github_auth_subparser = github_parser.add_argument_group("Authentication Modes")
    # Authentication Modes
    github_auth_subparser.add_argument(
        "--personal-access-token",
        nargs="?",
        help="Personal Access Token to log in against GitHub",
        default=None,
    )

    github_auth_subparser.add_argument(
        "--oauth-app-token",
        nargs="?",
        help="OAuth App Token to log in against GitHub",
        default=None,
    )

    # GitHub App Authentication
    github_auth_subparser.add_argument(
        "--github-app-id",
        nargs="?",
        help="GitHub App ID to log in against GitHub",
        default=None,
    )
    github_auth_subparser.add_argument(
        "--github-app-key",
        nargs="?",
        help="GitHub App Key Path to log in against GitHub",
        default=None,
    )
