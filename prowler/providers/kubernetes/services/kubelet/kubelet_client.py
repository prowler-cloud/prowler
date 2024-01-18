from prowler.providers.common.common import global_provider
from prowler.providers.kubernetes.services.kubelet.kubelet_service import Kubelet

kubelet_client = Kubelet(global_provider)
