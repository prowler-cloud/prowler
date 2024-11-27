def init_parser(self):
    """Init the Github Provider CLI parser"""
    github_parser = self.subparsers.add_parser(
        "github", parents=[self.common_providers_parser], help="GitHub Provider"
    )

    # Authentication Modes
    github_parser.add_argument(
        "--personal-access-token",
        nargs="?",
        help="Personal Access Token to log in against GitHub",
        default=None,
    )

    github_parser.add_argument(
        "--oauth-app-token",
        nargs="?",
        help="OAuth App Token to log in against GitHub",
        default=None,
    )

    # GitHub App Authentication
    github_parser.add_argument(
        "--github-app-id",
        nargs="?",
        help="GitHub App ID to log in against GitHub",
        default=None,
    )
    github_parser.add_argument(
        "--github-app-key",
        nargs="?",
        help="GitHub App Key to log in against GitHub",
        default=None,
    )

    # Validation function
    github_parser.set_defaults(func=validate_github_auth)


def validate_github_auth(self, args):
    """Validation for GitHub Authentication."""
    # Contar los métodos de autenticación utilizados
    auth_methods = sum(
        [
            args.personal_access_token is not None,
            args.oauth_app_token is not None,
            args.github_app_id is not None or args.github_app_key is not None,
        ]
    )

    if auth_methods == 0:
        raise ValueError(
            "You must specify at least one authentication method: "
            "--personal-access-token, --oauth-app-token, or both --github-app-id and --github-app-key."
        )

    if auth_methods > 1:
        raise ValueError(
            "You can only use one authentication method at a time: "
            "--personal-access-token, --oauth-app-token, or both --github-app-id and --github-app-key."
        )

    # Validar que ambos parámetros de GitHub App estén presentes si se elige este método
    if (args.github_app_id is not None or args.github_app_key is not None) and (
        args.github_app_id is None or args.github_app_key is None
    ):
        raise ValueError(
            "Both --github-app-id and --github-app-key must be provided for GitHub App Authentication."
        )
