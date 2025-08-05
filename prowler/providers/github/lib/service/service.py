import github
from github import Auth, Github, GithubIntegration
from github.GithubRetry import GithubRetry

from prowler.lib.logger import logger
from prowler.providers.github.github_provider import GithubProvider


class GithubService:
    def __init__(
        self,
        service: str,
        provider: GithubProvider,
    ):
        self.provider = provider
        self.clients = self.__set_clients__(
            provider.session,
        )

        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config

    def __set_clients__(self, session):
        clients = []
        try:
            retry_config = GithubRetry(total=3)
            if session.token:
                auth = Auth.Token(session.token)
                clients = [Github(auth=auth, retry=retry_config)]

            elif session.key and session.id:
                auth = Auth.AppAuth(
                    session.id,
                    session.key,
                )
                gi = GithubIntegration(auth=auth, retry=retry_config)

                for installation in gi.get_installations():
                    clients.append(installation.get_github_for_installation())

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return clients

    def _handle_github_api_error(
        self, error, context: str, item_name: str, reraise_rate_limit: bool = False
    ):
        """Centralized GitHub API error handling"""
        if isinstance(error, github.RateLimitExceededException):
            logger.error(f"Rate limit exceeded while {context} '{item_name}': {error}")
            if reraise_rate_limit:
                raise
        elif isinstance(error, github.GithubException):
            if "404" in str(error):
                logger.error(f"'{item_name}' not found or not accessible")
            elif "403" in str(error):
                logger.error(
                    f"Access denied to '{item_name}' - insufficient permissions"
                )
            else:
                logger.error(f"GitHub API error for '{item_name}': {error}")
        else:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_repositories_from_owner(self, client, name: str):
        """Get repositories from organization or user entity"""
        try:
            org = client.get_organization(name)
            return org.get_repos(), "organization"
        except github.GithubException as error:
            if "404" in str(error):
                logger.info(f"'{name}' not found as organization, trying as user...")
                try:
                    user = client.get_user(name)
                    return user.get_repos(), "user"
                except github.GithubException as user_error:
                    self._handle_github_api_error(
                        user_error, "accessing", f"{name} as user"
                    )
                    return [], "none"
                except Exception as user_error:
                    self._handle_github_api_error(
                        user_error, "accessing", f"{name} as user"
                    )
                    return [], "none"
            else:
                self._handle_github_api_error(error, "accessing organization", name)
                return [], "none"
        except Exception as error:
            self._handle_github_api_error(error, "accessing organization", name)
            return [], "none"
