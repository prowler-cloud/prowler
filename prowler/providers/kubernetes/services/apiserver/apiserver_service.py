from prowler.lib.logger import logger
from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider
from prowler.providers.kubernetes.lib.service.service import KubernetesService
from prowler.providers.kubernetes.services.core.core_client import core_client


################## APIServer ##################
class APIServer(KubernetesService):
    def __init__(self, provider: KubernetesProvider):
        super().__init__(provider)
        self.client = core_client

        self.apiserver_pods = self.__get_apiserver_pods__()

    def __get_apiserver_pods__(self):
        try:
            apiserver_pods = []
            for pod in self.client.pods.values():
                if pod.namespace == "kube-system" and pod.name.startswith(
                    "kube-apiserver"
                ):
                    apiserver_pods.append(pod)
            return apiserver_pods
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
