from kubernetes import client
from pydantic import BaseModel

from prowler.providers.kubernetes.lib.service.service import KubernetesService


################## Controller Manager
class Core(KubernetesService):
    def __init__(self, audit_info):
        super().__init__(audit_info)
        self.client = client.CoreV1Api(self.api_client)

        self.pods = []
        self.__get_pods__()

    def __get_pods__(self):
        print(self.client.list_pod_for_all_namespaces())
        # try:
        #     for pod in self.client.list_pod_for_all_namespaces():
        #         self.pods.append(
        #             Pod(
        #                 name=key["displayName"],
        #                 id=key["uid"],
        #                 creation_time=key["createTime"],
        #                 restrictions=key.get("restrictions", {}),
        #                 project_id=project_id,
        #             )
        #         )
        # except Exception as error:
        #     logger.error(
        #         f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        #     )


class Pod(BaseModel):
    name: str
    id: str
    creation_time: str
    restrictions: dict
    project_id: str
