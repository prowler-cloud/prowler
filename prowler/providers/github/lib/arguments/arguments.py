def init_parser(self):
    """Init the Github Provider CLI parser"""
    github_parser = self.subparsers.add_parser(
        "github", parents=[self.common_providers_parser], help="GitHub Provider"
    )
    # Authentication Modes
    github_auth_subparser = github_parser.add_argument_group("Authentication Modes")
    github_auth_modes_group = github_auth_subparser.add_mutually_exclusive_group()
    github_auth_modes_group.add_argument(
        "--personal-access-token",
        action="store_true",
        help="Use Personal Access Token to log in against GitHub",
        default=True,
    )
    github_auth_modes_group.add_argument(
        "--oauth-app",
        action="store_true",
        help="Use Oauth app token to log in against GitHub",
        default=False,
    )
    github_auth_modes_group.add_argument(
        "--github-app",
        action="store_true",
        help="Use GitHub app token to log in against GitHub",
        default=False,
    )
