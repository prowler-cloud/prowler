from kubernetes import client
from mock import MagicMock

from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider
from prowler.providers.kubernetes.models import (
    KubernetesIdentityInfo,
    KubernetesSession,
)


def set_mocked_kubernetes_provider() -> KubernetesProvider:
    provider = MagicMock()

    provider.identity = KubernetesIdentityInfo(context=None, cluster=None, user=None)
    provider.identity.context = None
    provider.session = KubernetesSession(api_client=client.ApiClient, context=None)

    return provider
