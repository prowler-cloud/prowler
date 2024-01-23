from typing import Any, List, Optional

from kubernetes import client
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.kubernetes.lib.service.service import KubernetesService


################## Rbac ##################
class Rbac(KubernetesService):
    def __init__(self, audit_info):
        super().__init__(audit_info)
        self.client = client.RbacAuthorizationV1Api()

        self.cluster_role_bindings = self.__list_cluster_role_bindings__()
        self.role_bindings = self.__list_role_bindings__()
        self.cluster_roles = self.__list_cluster_roles__()
        self.roles = self.__list_roles__()

    def __list_cluster_role_bindings__(self):
        try:
            bindings_list = []
            for binding in self.client.list_cluster_role_binding().items:
                # For each binding, create a ClusterRoleBinding object and append it to the list
                formatted_binding = {
                    "metadata": binding.metadata,
                    "subjects": []
                    if not binding.subjects
                    else [
                        {
                            "kind": subject.kind,
                            "name": subject.name,
                            "namespace": getattr(subject, "namespace", ""),
                            "metadata": getattr(subject, "metadata", None),
                        }
                        for subject in binding.subjects
                    ],
                    "roleRef": {
                        "kind": binding.role_ref.kind,
                        "name": binding.role_ref.name,
                        "apiGroup": binding.role_ref.api_group,
                    },
                }
                bindings_list.append(ClusterRoleBinding(**formatted_binding))
            return bindings_list
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_role_bindings__(self):
        try:
            role_bindings_list = []
            for binding in self.client.list_role_binding_for_all_namespaces().items:
                formatted_binding = {
                    "metadata": binding.metadata,
                    "subjects": [
                        {
                            "kind": subject.kind,
                            "name": subject.name,
                            "namespace": getattr(subject, "namespace", None),
                            "metadata": getattr(subject, "metadata", None),
                        }
                        for subject in binding.subjects
                    ],
                    "roleRef": {
                        "kind": binding.role_ref.kind,
                        "name": binding.role_ref.name,
                        "apiGroup": binding.role_ref.api_group,
                    },
                }
                role_bindings_list.append(RoleBinding(**formatted_binding))
            return role_bindings_list
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_roles__(self):
        try:
            roles_list = []
            for role in self.client.list_role_for_all_namespaces().items:
                formatted_role = {
                    "uid": role.metadata.uid,
                    "name": role.metadata.name,
                    "metadata": role.metadata,
                    "rules": [
                        {
                            "apiGroups": rule.api_groups,
                            "resources": rule.resources,
                            "verbs": rule.verbs,
                        }
                        for rule in role.rules
                    ],
                }
                roles_list.append(Role(**formatted_role))
            return roles_list
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_cluster_roles__(self):
        try:
            cluster_roles_list = []
            for role in self.client.list_cluster_role().items:
                formatted_role = {
                    "uid": role.metadata.uid,
                    "name": role.metadata.name,
                    "metadata": role.metadata,
                    "rules": [
                        {
                            "apiGroups": rule.api_groups,
                            "resources": rule.resources,
                            "verbs": rule.verbs,
                        }
                        for rule in role.rules
                    ],
                }
                cluster_roles_list.append(ClusterRole(**formatted_role))
            return cluster_roles_list
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Subject(BaseModel):
    kind: str
    name: str
    namespace: Optional[str]
    metadata: Any


class RoleRef(BaseModel):
    kind: str
    name: str
    apiGroup: str


class ClusterRoleBinding(BaseModel):
    metadata: Any
    subjects: List[Subject]
    roleRef: RoleRef


class RoleBinding(BaseModel):
    metadata: Any
    subjects: List[Subject]
    roleRef: RoleRef


class Rule(BaseModel):
    apiGroups: Optional[List[str]]
    resources: Optional[List[str]]
    verbs: Optional[List[str]]


class Role(BaseModel):
    name: str
    uid: str
    metadata: Any
    rules: List[Rule]


class ClusterRole(BaseModel):
    name: str
    uid: str
    metadata: Any
    rules: List[Rule]
