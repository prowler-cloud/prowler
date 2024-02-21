import os
import sys

from kubernetes import client, config

from prowler.lib.logger import logger


class Kubernetes_Provider:
    def __init__(self, kubeconfig_file: str, context: str, namespace: str):
        logger.info("Instantiating Kubernetes Provider ...")
        self.api_client, self.context = self.__set_credentials__(
            kubeconfig_file, context
        )
        if not self.api_client:
            logger.critical("Failed to set up a Kubernetes session.")
            sys.exit(1)
        if not namespace:
            self.namespaces = self.get_all_namespaces()
        else:
            self.namespaces = [namespace]

    def __set_credentials__(self, kubeconfig_file, input_context):
        try:
            if kubeconfig_file:
                # Use kubeconfig file if provided
                config.load_kube_config(
                    config_file=os.path.abspath(kubeconfig_file), context=input_context
                )
                # Set context if input in argument
                if input_context:
                    contexts = config.list_kube_config_contexts()[0]
                    for context_item in contexts:
                        if context_item["name"] == input_context:
                            context = context_item
                else:
                    # Get active context
                    context = config.list_kube_config_contexts()[1]
            else:
                # Otherwise try to load in-cluster config
                config.load_incluster_config()
                context = {
                    "name": "In-Cluster",
                    "context": {
                        "cluster": "in-cluster",  # Placeholder, as the real cluster name is not available
                        "user": "service-account-name",  # Also a placeholder
                    },
                }
            return client.ApiClient(), context
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            sys.exit(1)

    def get_credentials(self):
        return self.api_client, self.context

    def get_all_namespaces(self):
        """This function retrieves a list of all namespaces from a Kubernetes cluster."""
        try:
            v1 = client.CoreV1Api()
            namespace_list = v1.list_namespace()
            namespaces = [item.metadata.name for item in namespace_list.items]
            return namespaces
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def search_and_save_roles(
        self, roles: list, role_bindings, context_user: str, role_binding_type: str
    ):
        try:
            for rb in role_bindings:
                if rb.subjects:
                    for subject in rb.subjects:
                        if subject.kind == "User" and subject.name == context_user:
                            if role_binding_type == "ClusterRole":
                                roles.append(f"{role_binding_type}: {rb.role_ref.name}")
                            elif role_binding_type == "Role":
                                roles.append(
                                    f"{role_binding_type} ({rb.metadata.namespace}): {rb.role_ref.name}"
                                )
            return roles
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            sys.exit(1)

    def get_context_user_roles(self):
        try:
            rbac_api = client.RbacAuthorizationV1Api()
            context_user = self.context.get("context", {}).get("user", "")
            roles = []
            # Search in ClusterRoleBindings
            roles = self.search_and_save_roles(
                roles,
                rbac_api.list_cluster_role_binding().items,
                context_user,
                "ClusterRole",
            )

            # Search in RoleBindings for all namespaces
            roles = self.search_and_save_roles(
                roles,
                rbac_api.list_role_binding_for_all_namespaces().items,
                context_user,
                "Role",
            )
            return roles
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            sys.exit(1)
