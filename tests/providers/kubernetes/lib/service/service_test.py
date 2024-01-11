from kubernetes import client

from prowler.providers.common.models import Audit_Metadata
from prowler.providers.kubernetes.lib.audit_info.models import Kubernetes_Audit_Info
from prowler.providers.kubernetes.lib.service.service import KubernetesService


class Test_KubernetesService:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = Kubernetes_Audit_Info(
            api_client=client.ApiClient,
            context=None,
            audit_config=None,
            audit_resources=[],
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        return audit_info

    def test_KubernetesService_init(self):
        audit_info = self.set_mocked_audit_info()
        service = KubernetesService(audit_info)

        assert service.context is None
        assert service.api_client == client.ApiClient
