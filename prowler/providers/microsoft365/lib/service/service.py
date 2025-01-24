from msgraph import GraphServiceClient

from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider


class Microsoft365Service:
    def __init__(
        self,
        provider: Microsoft365Provider,
    ):
        self.client = GraphServiceClient(credentials=provider.session)

        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
