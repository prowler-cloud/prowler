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
        self.config_maps = []
        self.__list_config_maps__()
        self.nodes = []
        self.__list_nodes__()
        self.in_worker_node = self.__in_worker_node__()

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
                configmap_model = ConfigMap(
                    name=cm.metadata.name,
                    namespace=cm.metadata.namespace,
                    uid=cm.metadata.uid,
                    data=cm.data,
                    labels=cm.metadata.labels,
                    annotations=cm.metadata.annotations,
                )
                self.config_maps.append(configmap_model)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_nodes__(self):
        try:
            response = self.client.list_node()
            self.nodes = []
            for node in response.items:
                node_model = Node(
                    name=node.metadata.name,
                    uid=node.metadata.uid,
                    namespace=node.metadata.namespace
                    if node.metadata.namespace
                    else "cluster-wide",
                    labels=node.metadata.labels,
                    annotations=node.metadata.annotations,
                    unschedulable=node.spec.unschedulable,
                    node_info=node.status.node_info.to_dict()
                    if node.status.node_info
                    else None,
                )
                self.nodes.append(node_model)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __in_worker_node__(self):
        try:
            hostname = socket.gethostname()
            for node in self.nodes:
                if hostname == node.name:
                    node.inside = True
                    return True
            return False

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
    data: Optional[dict]
    labels: Optional[dict]
    annotations: Optional[dict]


class Node(BaseModel):
    name: str
    uid: str
    namespace: str
    labels: Optional[dict]
    annotations: Optional[dict]
    unschedulable: Optional[bool]
    node_info: Optional[dict]
    inside: bool = False
