from kubernetes import client

from prowler.providers.kubernetes.lib.service.service import KubernetesService
from tests.providers.kubernetes.audit_info_utils import set_mocked_audit_info


class Test_KubernetesService:
    def test_KubernetesService_init(self):
        audit_info = set_mocked_audit_info()
        service = KubernetesService(audit_info)

        assert service.context is None
        assert service.api_client == client.ApiClient
