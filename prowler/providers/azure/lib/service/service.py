from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed

from kiota_authentication_azure.azure_identity_authentication_provider import (
    AzureIdentityAuthenticationProvider,
)
from msgraph.graph_request_adapter import GraphRequestAdapter
from msgraph_core import GraphClientFactory

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

    def list_with_rg_scope(
        self,
        subscription_id: str,
        list_all_fn: Callable[[], Iterable[object]],
        list_by_rg_fn: Callable[..., Iterable[object]],
    ) -> list[object]:
        """List Azure resources using the provider resource group scope.

        Args:
            subscription_id: Subscription ID whose resource group scope should be used.
            list_all_fn: Callable that lists all resources in the subscription when
                no resource group filter is configured.
            list_by_rg_fn: Callable that lists resources for a single resource
                group. It must accept ``resource_group_name`` as a keyword argument.

        Returns:
            A list containing the resources returned by the selected Azure SDK
            list operation.
        """
        if not self.resource_groups:
            return list(list_all_fn())
        resource_groups = self.resource_groups.get(subscription_id, [])
        if not resource_groups:
            logger.info(
                f"No valid resource groups for subscription {subscription_id}, skipping."
            )
            return []
        output = []
        for resource_group in resource_groups:
            try:
                output += list(list_by_rg_fn(resource_group_name=resource_group))
            except Exception as error:
                logger.warning(
                    f"Subscription ID: {subscription_id} -- Resource Group: {resource_group} -- "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return output

    def __set_clients__(self, identity, session, service, region_config):
        clients = {}
        try:
            if "GraphServiceClient" in str(service):
                # GraphServiceClient(credentials, scopes=...) only customises the
                # OAuth scope; the underlying httpx client's base URL stays at
                # graph.microsoft.com. For sovereign clouds we must also point
                # the HTTP transport at the per-cloud host, which is done by
                # building a custom GraphRequestAdapter with a NationalClouds
                # base URL.
                auth_provider = AzureIdentityAuthenticationProvider(
                    session, scopes=[region_config.graph_scope]
                )
                http_client = GraphClientFactory.create_with_default_middleware(
                    host=region_config.graph_host
                )
                request_adapter = GraphRequestAdapter(auth_provider, client=http_client)
                clients.update(
                    {identity.tenant_domain: service(request_adapter=request_adapter)}
                )
            elif "LogsQueryClient" in str(service):
                for subscription_id, display_name in identity.subscriptions.items():
                    clients.update(
                        {
                            subscription_id: service(
                                credential=session,
                                endpoint=region_config.logs_endpoint,
                            )
                        }
                    )
            else:
                for subscription_id, display_name in identity.subscriptions.items():
                    clients.update(
                        {
                            subscription_id: service(
                                credential=session,
                                subscription_id=subscription_id,
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
