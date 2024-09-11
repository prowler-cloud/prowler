import yaml

from prowler.lib.logger import logger
from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider
from prowler.providers.kubernetes.lib.service.service import KubernetesService
from prowler.providers.kubernetes.services.core.core_client import core_client


################## Kubelet ##################
class Kubelet(KubernetesService):
    def __init__(self, provider: KubernetesProvider):
        super().__init__(provider)
        self.client = core_client

        self.kubelet_config_maps = self._get_kubelet_config_maps()

    def _get_kubelet_config_maps(self):
        try:
            kubelet_config_maps = []
            for cm in self.client.config_maps.values():
                if cm.name.startswith("kubelet-config"):
                    cm.kubelet_args = yaml.safe_load(cm.data.get("kubelet", ""))
                    if not cm.kubelet_args:
                        cm.kubelet_args = []
                    kubelet_config_maps.append(cm)
            return kubelet_config_maps
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
