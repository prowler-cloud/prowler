from concurrent.futures import ThreadPoolExecutor, as_completed

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider

MAX_WORKERS = 10


class AzureService:
    def __init__(
        self,
        service: str,
        provider: AzureProvider,
    ):
        self.clients = self.__set_clients__(
            provider.identity,
            provider.session,
            service,
            provider.region_config,
        )

        self.subscriptions = provider.identity.subscriptions
        self.locations = provider.locations
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config

        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def __threading_call__(self, call, iterator):
        """Execute a function across multiple items using threading."""
        items = list(iterator) if not isinstance(iterator, list) else iterator

        futures = {self.thread_pool.submit(call, item): item for item in items}
        results = []

        for future in as_completed(futures):
            try:
                result = future.result()
                if result is not None:
                    results.append(result)
            except Exception:
                pass

        return results

    def __set_clients__(self, identity, session, service, region_config):
        clients = {}
        try:
            if "GraphServiceClient" in str(service):
                clients.update({identity.tenant_domain: service(credentials=session)})
            elif "LogsQueryClient" in str(service):
                for display_name, id in identity.subscriptions.items():
                    clients.update({display_name: service(credential=session)})
            else:
                for display_name, id in identity.subscriptions.items():
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
