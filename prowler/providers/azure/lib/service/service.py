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
        self.resource_groups = provider.resource_groups
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

    def list_with_rg_scope(self, subscription_name, list_all_fn, list_by_rg_fn):
        if not self.resource_groups:
            return list(list_all_fn())
        resource_groups = self.resource_groups.get(subscription_name, [])
        if not resource_groups:
            logger.warning(
                f"No valid resource groups for subscription {subscription_name}"
            )
            return []
        output = []
        for resource_group in resource_groups:
            try:
                output += list(list_by_rg_fn(resource_group_name=resource_group))
            except Exception as error:
                logger.warning(
                    f"Subscription name: {subscription_name} -- Resource Group: {resource_group} -- "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return output

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
