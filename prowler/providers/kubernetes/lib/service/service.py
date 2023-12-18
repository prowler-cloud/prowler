import threading

from prowler.providers.kubernetes.kubernetes_provider_new import KubernetesProvider


class KubernetesService:
    def __init__(self, provider: KubernetesProvider):
        self.context = provider.context
        self.api_client = provider.api_client

    def __get_api_client__(self):
        return self.api_client

    def __threading_call__(self, call, iterator):
        threads = []
        for value in iterator:
            threads.append(threading.Thread(target=call, args=(value,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
