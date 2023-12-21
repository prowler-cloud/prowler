from typing import List, Optional

from kubernetes import client
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.kubernetes.lib.service.service import KubernetesService


################## Core ##################
class Core(KubernetesService):
    def __init__(self, audit_info):
        super().__init__(audit_info)
        self.client = client.CoreV1Api(self.api_client)

        self.pods = []
        self.__get_pods__()

    def __get_pods__(self):
        try:
            pods = self.client.list_pod_for_all_namespaces()
            for pod in pods.items:
                pod_containers = []
                for container in pod.spec.containers:
                    pod_containers.append(
                        Container(
                            name=container.name,
                            image=container.image,
                            command=container.command if container.command else None,
                            ports=[
                                {"containerPort": port.container_port}
                                for port in container.ports
                            ]
                            if container.ports
                            else None,
                            env=[
                                {"name": env.name, "value": env.value}
                                for env in container.env
                            ]
                            if container.env
                            else None,
                        )
                    )
                self.pods.append(
                    Pod(
                        name=pod.metadata.name,
                        namespace=pod.metadata.namespace,
                        labels=pod.metadata.labels,
                        annotations=pod.metadata.annotations,
                        node_name=pod.spec.node_name,
                        service_account=pod.spec.service_account_name,
                        status_phase=pod.status.phase,
                        pod_ip=pod.status.pod_ip,
                        host_ip=pod.status.host_ip,
                        containers=pod_containers,
                    )
                )
                # print(f"Pod Name: {pod.metadata.name}, Namespace: {pod.metadata.namespace}")
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Container(BaseModel):
    name: str
    image: str
    command: Optional[List[str]] = None
    ports: Optional[List[dict]] = None
    env: Optional[List[dict]] = None


class Pod(BaseModel):
    name: str
    namespace: str
    labels: Optional[dict] = None
    annotations: Optional[dict] = None
    node_name: Optional[str] = None
    service_account: Optional[str] = None
    status_phase: Optional[str] = None
    pod_ip: Optional[str] = None
    host_ip: Optional[str] = None
    containers: Optional[List[Container]] = None
