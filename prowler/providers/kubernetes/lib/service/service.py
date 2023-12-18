import threading

from kubernetes import client


class KubernetesService:
    def __init__(self, provider):
        self.api_client = provider.session
        self.context = provider.context
        self.client = client.CoreV1Api(self.api_client)

    def __get_client__(self):
        return self.client

    def __threading_call__(self, call, iterator):
        threads = []
        for value in iterator:
            threads.append(threading.Thread(target=call, args=(value,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
