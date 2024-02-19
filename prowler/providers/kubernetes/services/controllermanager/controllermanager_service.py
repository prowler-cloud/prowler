from prowler.lib.logger import logger
from prowler.providers.kubernetes.lib.service.service import KubernetesService
from prowler.providers.kubernetes.services.core.core_client import core_client


################## ControllerManager ##################
class ControllerManager(KubernetesService):
    def __init__(self, audit_info):
        super().__init__(audit_info)
        self.client = core_client

        self.controllermanager_pods = self.__get_controllermanager_pods__()

    def __get_controllermanager_pods__(self):
        try:
            controllermanager_pods = []
            for pod in self.client.pods.values():
                if pod.namespace == "kube-system" and pod.name.startswith(
                    "kube-controller-manager"
                ):
                    controllermanager_pods.append(pod)
            return controllermanager_pods
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
