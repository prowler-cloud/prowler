from github import Auth, Github

from prowler.lib.logger import logger
from prowler.providers.github.github_provider import GithubProvider


class GithubService:
    def __init__(
        self,
        service: str,
        provider: GithubProvider,
    ):
        self.client = self.__set_client__(
            provider.identity,
            provider.session,
            service,
        )

        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config

    def __set_client__(self, session):
        try:
            auth = Auth.Token(session.token)
            client = Github(auth=auth)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return client
