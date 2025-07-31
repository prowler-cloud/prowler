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
        metavar="GITHUB_PERSONAL_ACCESS_TOKEN",
    )

    github_auth_subparser.add_argument(
        "--oauth-app-token",
        nargs="?",
        help="OAuth App Token to log in against GitHub",
        default=None,
        metavar="GITHUB_OAUTH_APP_TOKEN",
    )

    # GitHub App Authentication
    github_auth_subparser.add_argument(
        "--github-app-id",
        nargs="?",
        help="GitHub App ID to log in against GitHub",
        default=None,
        metavar="GITHUB_APP_ID",
    )
    github_auth_subparser.add_argument(
        "--github-app-key-path",
        nargs="?",
        help="Path to GitHub App private key file",
        default=None,
        metavar="GITHUB_APP_KEY_PATH",
    )
    github_auth_subparser.add_argument(
        "--github-app-key",
        nargs="?",
        help="GitHub App private key content",
        default=None,
        metavar="GITHUB_APP_KEY_CONTENT",
    )

    github_scoping_subparser = github_parser.add_argument_group("Scan Scoping")
    github_scoping_subparser.add_argument(
        "--repository",
        "--repositories",
        nargs="*",
        help="Repository name(s) to scan in 'owner/repo-name' format",
        default=None,
        metavar="REPOSITORY",
    )
    github_scoping_subparser.add_argument(
        "--organization",
        "--organizations",
        nargs="*",
        help="Organization or user name(s) to scan repositories for",
        default=None,
        metavar="ORGANIZATION",
    )
