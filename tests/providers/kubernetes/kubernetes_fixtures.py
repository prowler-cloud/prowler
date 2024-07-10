from mock import MagicMock

from kubernetes import client
from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider
from prowler.providers.kubernetes.models import (
    KubernetesIdentityInfo,
    KubernetesSession,
)

KUBERNETES_CLUSTER_NAME = "test-cluster"
KUBERNETES_NAMESPACE = "test-namespace"
KUBERNETES_CONFIG = {
    "audit_log_maxbackup": 10,
    "audit_log_maxsize": 100,
    "audit_log_maxage": 30,
    "apiserver_strong_ciphers": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
    ],
    "kubelet_strong_ciphers": [
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
    ],
}


def set_mocked_kubernetes_provider() -> KubernetesProvider:
    provider = MagicMock()

    provider.type = "kubernetes"
    provider.identity = KubernetesIdentityInfo(context=None, cluster=None, user=None)
    provider.identity.context = None
    provider.session = KubernetesSession(api_client=client.ApiClient, context=None)

    return provider
