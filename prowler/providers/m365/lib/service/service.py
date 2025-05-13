from msgraph import GraphServiceClient

from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
from prowler.providers.m365.m365_provider import M365Provider


class M365Service:
    def __init__(
        self,
        provider: M365Provider,
    ):
        self.client = GraphServiceClient(credentials=provider.session)
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config

        # Initialize PowerShell client only if credentials are available
        self.powershell = (
            M365PowerShell(provider.credentials) if provider.credentials else None
        )
