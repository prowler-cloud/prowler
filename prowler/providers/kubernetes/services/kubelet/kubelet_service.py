from prowler.lib.logger import logger
from prowler.providers.kubernetes.lib.service.service import KubernetesService
from prowler.providers.kubernetes.services.core.core_client import core_client


################## Kubelet ##################
class Kubelet(KubernetesService):
    def __init__(self, audit_info):
        super().__init__(audit_info)
        self.client = core_client

        self.kubelet_config_maps = self.__get_kubelet_config_maps__()

    def __get_kubelet_config_maps__(self):
        try:
            kubelet_config_maps = []
            for cm in self.client.config_maps:
                if cm.name.startswith("kubelet-config"):
                    kubelet_config_maps.append(cm)
            return kubelet_config_maps
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
