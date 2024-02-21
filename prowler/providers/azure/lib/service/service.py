from prowler.lib.logger import logger
from prowler.providers.azure.lib.audit_info.models import Azure_Audit_Info


class AzureService:
    def __init__(
        self,
        service: str,
        audit_info: Azure_Audit_Info,
    ):
        self.clients = self.__set_clients__(
            audit_info.identity.subscriptions,
            audit_info.credentials,
            service,
            audit_info.azure_region_config,
        )

        self.subscriptions = audit_info.identity.subscriptions
        self.locations = audit_info.locations

    def __set_clients__(self, subscriptions, credentials, service, region_config):
        clients = {}
        try:
            for display_name, id in subscriptions.items():
                clients.update(
                    {
                        display_name: service(
                            credential=credentials,
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
