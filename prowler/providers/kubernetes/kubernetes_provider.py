import os
import sys

from kubernetes import client, config

from prowler.lib.logger import logger


class Kubernetes_Provider:
    def __init__(
        self,
        kubeconfig_file: str,
        context: list,
    ):
        logger.info("Instantiating Kubernetes Provider ...")
        self.api_client, self.context = self.__set_credentials__(
            kubeconfig_file, context
        )
        if not self.api_client:
            logger.critical("Failed to set up a Kubernetes session.")
            sys.exit(1)

    def __set_credentials__(self, kubeconfig_file, context):
        try:
            if kubeconfig_file:
                # Use kubeconfig file if provided
                config.load_kube_config(
                    config_file=os.path.abspath(kubeconfig_file), context=context
                )
            else:
                # Otherwise try to load in-cluster config
                config.load_incluster_config()
            context = config.list_kube_config_contexts()[0][0]
            return client.ApiClient(), context
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            sys.exit(1)

    def get_credentials(self):
        return self.api_client, self.context

    def get_context_user_roles(self):
        try:
            rbac_api = client.RbacAuthorizationV1Api()
            context_user = self.context.get("context").get("user")
            roles = []

            # Search in ClusterRoleBindings
            cluster_role_bindings = rbac_api.list_cluster_role_binding()
            for crb in cluster_role_bindings.items:
                if crb.subjects:
                    for subject in crb.subjects:
                        if subject.kind == "User" and subject.name == context_user:
                            roles.append(f"ClusterRole: {crb.role_ref.name}")

            # Search in RoleBindings for all namespaces
            role_bindings = rbac_api.list_role_binding_for_all_namespaces()
            for rb in role_bindings.items:
                for subject in rb.subjects:
                    if subject.kind == "User" and subject.name == context_user:
                        roles.append(
                            f"Role ({rb.metadata.namespace}): {rb.role_ref.name}"
                        )

            return roles
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            sys.exit(1)
