from msgraph import GraphServiceClient

from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider


class Microsoft365Service:
    def __init__(
        self,
        provider: Microsoft365Provider,
    ):
        self.client = GraphServiceClient(credentials=provider.session)

        # self.locations = provider.locations
        self.audited_tenant = provider.identity.tenant_id
        self.audited_domain = provider.identity.tenant_domain
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
