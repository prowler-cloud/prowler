from msal import ConfidentialClientApplication
from msgraph import GraphServiceClient

from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider


class Microsoft365Service:
    def __init__(
        self,
        provider: Microsoft365Provider,
    ):
        self.client = GraphServiceClient(credentials=provider.session)
        self.credentials = provider.session.credentials[0]._credential
        self.identity = provider.identity
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config

    def get_headers(self, endpoint: str):
        """
        Get headers for a given endpoint to craft requests from services
        """

        try:
            app = ConfidentialClientApplication(
                client_id=self.credentials._client_id,
                authority=f"https://login.microsoftonline.com/{self.credentials._tenant_id}",
                client_credential=self.credentials._client_credential,
            )
            token_result = app.acquire_token_for_client(scopes=[endpoint])

            return {
                "Authorization": f"Bearer {token_result['access_token']}",
                "Content-Type": "application/json",
            }
        except Exception as e:
            raise Exception(f"Error getting headers: {e}")
