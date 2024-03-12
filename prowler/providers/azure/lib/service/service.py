from prowler.lib.logger import logger
from prowler.providers.azure.lib.audit_info.models import Azure_Audit_Info


class AzureService:
    def __init__(
        self,
        services: list,
        audit_info: Azure_Audit_Info,
    ):
        if not isinstance(services, list):
            services = [services]

        self.clients = self.__set_clients__(
            audit_info.identity,
            audit_info.credentials,
            services,
            audit_info.azure_region_config,
        )

        self.subscriptions = audit_info.identity.subscriptions
        self.locations = audit_info.locations

        self.audit_config = audit_info.audit_config

    def __set_clients__(self, identity, credentials, services, region_config):
        clients = {}
        try:
            if "GraphServiceClient" in str(services):
                clients.update({identity.domain: {}})
                for client_service in services:
                    if "msgraph_beta." in str(client_service):
                        clients[identity.domain].update(
                            {"beta": client_service(credentials=credentials)}
                        )
                    elif "msgraph." in str(client_service):
                        clients[identity.domain].update(
                            {"v1": client_service(credentials=credentials)}
                        )
                    else:
                        clients[identity.domain].update(
                            {
                                str(client_service): client_service(
                                    credentials=credentials
                                )
                            }
                        )

            else:
                for display_name, id in identity.subscriptions.items():
                    clients.update(
                        {
                            display_name: services[
                                0
                            ](  # Not Entra services only support the first client
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
