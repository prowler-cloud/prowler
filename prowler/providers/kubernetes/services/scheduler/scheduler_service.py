from prowler.lib.logger import logger
from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider
from prowler.providers.kubernetes.lib.service.service import KubernetesService
from prowler.providers.kubernetes.services.core.core_client import core_client


class Scheduler(KubernetesService):
    def __init__(self, provider: KubernetesProvider):
        super().__init__(provider)
        self.client = core_client

        self.scheduler_pods = self._get_scheduler_pods()

    def _get_scheduler_pods(self):
        """Collect the `kube-scheduler` pods from the `kube-system` namespace.

        Returns:
            list: Matching pods. Any pods collected before an error are kept, so
            the checks always receive an iterable instead of `None`.
        """
        scheduler_pods = []
        try:
            for pod in self.client.pods.values():
                if pod.namespace == "kube-system" and pod.name.startswith(
                    "kube-scheduler"
                ):
                    scheduler_pods.append(pod)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return scheduler_pods
