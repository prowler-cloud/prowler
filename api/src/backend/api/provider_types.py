from functools import lru_cache

from prowler.providers.common.provider import Provider as SDKProvider


@lru_cache(maxsize=1)
def get_app_provider_types():
    """App-facing provider types: SDK providers with ``sdk_only = False``.

    Single source of truth for which provider types the API exposes (filter
    choices, serializer field, creation validation). Cached for the process
    lifetime; hot-installing a provider needs cache invalidation (tracked
    separately) to show up without a restart.
    """
    return tuple(SDKProvider.get_app_providers())


@lru_cache(maxsize=1)
def get_provider_type_choices():
    """Provider-type choices from the app-facing providers, hiding providers
    the API does not expose (``sdk_only = True``). Shared by the filters and
    the provider serializer."""
    return [(name, name) for name in get_app_provider_types()]
