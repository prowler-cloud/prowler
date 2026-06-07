from functools import lru_cache

from prowler.providers.common.provider import Provider as SDKProvider


@lru_cache(maxsize=1)
def get_provider_type_choices():
    """Provider-type choices from the SDK's available providers, so they cover
    external providers and not just a static enum.

    Cached for the process lifetime; hot-installing a provider needs
    coordinated cache invalidation (tracked separately) to show up here without
    a restart. Shared by the filters and the provider serializer.
    """
    return [(name, name) for name in SDKProvider.get_available_providers()]
