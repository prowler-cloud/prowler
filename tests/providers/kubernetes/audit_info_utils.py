from kubernetes import client

from prowler.providers.common.models import Audit_Metadata
from prowler.providers.kubernetes.lib.audit_info.models import Kubernetes_Audit_Info


# Mocked Kubernetes Audit Info
def set_mocked_audit_info():
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
