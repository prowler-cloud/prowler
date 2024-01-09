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

        self.cluster_role_bindings = self.__list_cluster_role_binding__()

    def __list_cluster_role_binding__(self):
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
                            "namespace": getattr(subject, "namespace", None),
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


class Subject(BaseModel):
    kind: str
    name: str
    namespace: Optional[str] = None


class RoleRef(BaseModel):
    kind: str
    name: str
    apiGroup: str


class ClusterRoleBinding(BaseModel):
    metadata: Any
    subjects: List[Subject]
    roleRef: RoleRef
