from prowler.lib.logger import logger
from prowler.providers.kubernetes.lib.service.service import KubernetesService
from prowler.providers.kubernetes.services.core.core_client import core_client


################## APIServer ##################
class APIServer(KubernetesService):
    def __init__(self, audit_info):
        super().__init__(audit_info)
        self.client = core_client

        self.apiserver_pod = self.__get_apiserver_pod__()

    def __get_apiserver_pod__(self):
        try:
            for pod in self.client.pods:
                if pod.namespace == "kube-system" and pod.name.startswith(
                    "kube-apiserver"
                ):
                    return pod
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
