from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider_new import AzureProvider


class AzureService:
    def __init__(
        self,
        service: str,
        audit_info: AzureProvider,
    ):
        self.clients = self.__set_clients__(
            audit_info.identity.subscriptions,
            audit_info.session,
            service,
            audit_info.region_config,
        )

        self.subscriptions = audit_info.identity.subscriptions

    def __set_clients__(self, subscriptions, session, service, region_config):
        clients = {}
        try:
            for display_name, id in subscriptions.items():
                clients.update(
                    {
                        display_name: service(
                            credential=session,
                            subscription_id=id,
                            base_url=region_config.base_url,
                            credential_scopes=region_config.credential_scopes,
                        )
                    }
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        else:
            return clients
