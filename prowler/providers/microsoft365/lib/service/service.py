from msgraph import GraphServiceClient

from prowler.lib.logger import logger
from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider


class Microsoft365Service:
    def __init__(
        self,
        provider: Microsoft365Provider,
    ):
        self.clients = self.__set_clients__(
            provider.identity,
            provider.session,
            provider.region_config,
        )

        # self.locations = provider.locations
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config

    def __set_clients__(self, identity, session, region_config):
        clients = {}
        try:
            clients.update(
                {identity.tenant_domain: GraphServiceClient(credentials=session)}
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        else:
            return clients
