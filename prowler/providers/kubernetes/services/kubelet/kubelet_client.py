from prowler.providers.common.common import get_global_provider
from prowler.providers.kubernetes.services.kubelet.kubelet_service import Kubelet

kubelet_client = Kubelet(get_global_provider())
