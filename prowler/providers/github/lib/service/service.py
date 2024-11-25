from github import Auth, Github, GithubIntegration

from prowler.lib.logger import logger
from prowler.providers.github.github_provider import GithubProvider


class GithubService:
    def __init__(
        self,
        service: str,
        provider: GithubProvider,
    ):
        self.client = self.__set_client__(
            provider.session,
        )

        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config

    def __set_client__(self, session):
        try:
            if session.token:
                auth = Auth.Token(session.token)
                client = Github(auth=auth)

            elif session.key and session.id:
                auth = Auth.GithubApp(
                    session.github_app_id,
                    session.github_app_key,
                )
                client = GithubIntegration(auth=auth)

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return client
