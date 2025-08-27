from prowler.lib.logger import logger


def init_parser(self):
    """Initialize the GitHub Action Provider parser to add all the arguments and flags.
    
    Receives a ProwlerArgumentParser object and fills it.
    """
    github_action_parser = self.subparsers.add_parser(
        "github_action",
        parents=[self.common_providers_parser],
        help="GitHub Action provider for scanning GitHub Actions workflows security",
    )

    github_action_auth_subparser = github_action_parser.add_argument_group(
        "Authentication"
    )
    github_action_auth_subparser.add_argument(
        "--github-username",
        nargs="?",
        default=None,
        help="GitHub username for authentication when cloning private repositories",
    )
    github_action_auth_subparser.add_argument(
        "--personal-access-token",
        nargs="?",
        default=None,
        help="GitHub personal access token for authentication when cloning private repositories",
    )
    github_action_auth_subparser.add_argument(
        "--oauth-app-token",
        nargs="?",
        default=None,
        help="GitHub OAuth App token for authentication when cloning private repositories",
    )

    github_action_scan_subparser = github_action_parser.add_argument_group(
        "Scan Configuration"
    )
    github_action_scan_subparser.add_argument(
        "--workflow-path",
        "--scan-path",
        nargs="?",
        default=".",
        help="Path to the directory containing GitHub Actions workflow files (default: current directory)",
    )
    github_action_scan_subparser.add_argument(
        "--repository-url",
        "--scan-repository-url",
        nargs="?",
        default=None,
        help="URL of the GitHub repository to scan (e.g., https://github.com/user/repo)",
    )
    github_action_scan_subparser.add_argument(
        "--exclude-workflows",
        "--exclude-path",
        nargs="+",
        default=[],
        help="List of workflow files or patterns to exclude from scanning",
    )


def validate_arguments(arguments):
    """Validate the arguments for the GitHub Action provider."""
    
    # Check if both local path and repository URL are provided
    if hasattr(arguments, "workflow_path") and hasattr(arguments, "repository_url"):
        if arguments.repository_url and arguments.workflow_path != ".":
            return (
                False,
                "Cannot specify both --workflow-path and --repository-url. Please choose one.",
            )
    
    # Check authentication when using repository URL
    if hasattr(arguments, "repository_url") and arguments.repository_url:
        has_github_auth = False
        
        if hasattr(arguments, "github_username") and hasattr(arguments, "personal_access_token"):
            if arguments.github_username and arguments.personal_access_token:
                has_github_auth = True
                
        if hasattr(arguments, "oauth_app_token") and arguments.oauth_app_token:
            has_github_auth = True
        
        # Note: Authentication is optional for public repositories
        if not has_github_auth:
            logger.info(
                "No GitHub authentication provided. Only public repositories will be accessible."
            )
    
    return (True, "")