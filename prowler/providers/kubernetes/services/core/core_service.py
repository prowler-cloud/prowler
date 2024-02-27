import socket
from typing import Any, List, Optional

from kubernetes import client
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.kubernetes.lib.service.service import KubernetesService


################## Core ##################
class Core(KubernetesService):
    def __init__(self, audit_info):
        super().__init__(audit_info)
        self.client = client.CoreV1Api(self.api_client)

        self.pods = {}
        self.__get_pods__()
        self.config_maps = {}
        self.__list_config_maps__()

    def __get_pods__(self):
        try:
            pods = self.client.list_pod_for_all_namespaces()
            for pod in pods.items:
                pod_containers = {}
                for container in (
                    pod.spec.containers + pod.spec.init_containers
                    if pod.spec.init_containers
                    else [] + pod.spec.ephemeral_containers
                    if pod.spec.ephemeral_containers
                    else []
                ):
                    pod_containers[container.name] = Container(
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
                self.pods[pod.metadata.uid] = Pod(
                    name=pod.metadata.name,
                    uid=pod.metadata.uid,
                    namespace=pod.metadata.namespace,
                    labels=pod.metadata.labels,
                    annotations=pod.metadata.annotations,
                    node_name=pod.spec.node_name,
                    service_account=pod.spec.service_account_name,
                    status_phase=pod.status.phase,
                    pod_ip=pod.status.pod_ip,
                    host_ip=pod.status.host_ip,
                    host_pid=pod.spec.host_pid,
                    host_ipc=pod.spec.host_ipc,
                    host_network=pod.spec.host_network,
                    security_context=pod.spec.security_context,
                    containers=pod_containers,
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_config_maps__(self):
        try:
            response = self.client.list_config_map_for_all_namespaces()
            for cm in response.items:
                self.config_maps[cm.metadata.uid] = ConfigMap(
                    name=cm.metadata.name,
                    namespace=cm.metadata.namespace,
                    uid=cm.metadata.uid,
                    data=cm.data,
                    labels=cm.metadata.labels,
                    annotations=cm.metadata.annotations,
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Container(BaseModel):
    name: str
    image: str
    command: Optional[List[str]]
    ports: Optional[List[dict]]
    env: Optional[List[dict]]


class Pod(BaseModel):
    name: str
    uid: str
    namespace: str
    labels: Optional[dict]
    annotations: Optional[dict]
    node_name: Optional[str]
    service_account: Optional[str]
    status_phase: Optional[str]
    pod_ip: Optional[str]
    host_ip: Optional[str]
    host_pid: Optional[str]
    host_ipc: Optional[str]
    host_network: Optional[str]
    security_context: Optional[Any]
    containers: Optional[dict]


class ConfigMap(BaseModel):
    name: str
    namespace: str
    uid: str
    data: dict = {}
    labels: Optional[dict]
    kubelet_args: list = []
    annotations: Optional[dict]
