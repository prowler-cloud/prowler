# This file needs to be named with the provider at the beginning since there is a limitation in pytest and two tests files cannot have the same name
# https://github.com/pytest-dev/pytest/issues/774#issuecomment-112343498
from kubernetes import client

from prowler.providers.kubernetes.lib.service.service import KubernetesService
from tests.providers.kubernetes.kubernetes_fixtures import (
    set_mocked_kubernetes_provider,
)


class TestKubernetesService:
    def test_KubernetesService_init(self):
        kubernetes_provider = set_mocked_kubernetes_provider()
        service = KubernetesService(kubernetes_provider)

        assert service.context is None
        assert service.api_client == client.ApiClient
