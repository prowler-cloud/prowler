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
