import os
import sys
from typing import Any, Optional

from colorama import Fore, Style
from kubernetes import client, config

from prowler.lib.logger import logger
from prowler.providers.common.provider import CloudProvider


class KubernetesProvider(CloudProvider):
    api_client: Any
    context: dict
    namespaces: list
    audit_resources: Optional[Any]
    audit_metadata: Optional[Any]
    audit_config: Optional[dict]

    def __init__(self, arguments: dict):
        """
        Initializes the KubernetesProvider instance.

        Args:
            arguments (dict): A dictionary containing configuration arguments.
        """
        logger.info("Instantiating Kubernetes Provider ...")

        self.api_client, self.context = self.setup_session(
            arguments.kubeconfig_file, arguments.context
        )
        if not arguments.namespaces:
            logger.info("Retrieving all namespaces ...")
            self.namespaces = self.get_all_namespaces()
        else:
            self.namespaces = arguments.namespaces

        if not self.api_client:
            logger.critical("Failed to set up a Kubernetes session.")
            sys.exit(1)
        if not arguments.only_logs:
            self.print_credentials()

    def setup_session(self, kubeconfig_file, input_context):
        """
        Sets up the Kubernetes session.

        Args:
            kubeconfig_file (str): Path to the kubeconfig file.
            input_context (str): Context name.

        Returns:
            Tuple: A tuple containing the API client and the context.
        """
        try:
            if kubeconfig_file:
                logger.info(f"Using kubeconfig file: {kubeconfig_file}")
                config.load_kube_config(
                    config_file=os.path.abspath(kubeconfig_file), context=input_context
                )
                if input_context:
                    contexts = config.list_kube_config_contexts()[0]
                    for context_item in contexts:
                        if context_item["name"] == input_context:
                            context = context_item
                else:
                    context = config.list_kube_config_contexts()[1]
            else:
                logger.info("Using in-cluster config")
                config.load_incluster_config()
                context = {
                    "name": "In-Cluster",
                    "context": {
                        "cluster": "in-cluster",
                        "user": "service-account-name",
                    },
                }
            return client.ApiClient(), context
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            sys.exit(1)

    def search_and_save_roles(
        self, roles: list, role_bindings, context_user: str, role_binding_type: str
    ):
        """
        Searches for and saves roles.

        Args:
            roles (list): A list to save the roles.
            role_bindings: Role bindings.
            context_user (str): Context user.
            role_binding_type (str): Role binding type.

        Returns:
            list: A list containing the roles.
        """
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
        """
        Retrieves the context user roles.

        Returns:
            list: A list containing the context user roles.
        """
        try:
            rbac_api = client.RbacAuthorizationV1Api()
            context_user = self.context.get("context", {}).get("user", "")
            roles = []
            roles = self.search_and_save_roles(
                roles,
                rbac_api.list_cluster_role_binding().items,
                context_user,
                "ClusterRole",
            )

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

    def get_all_namespaces(self):
        """
        Retrieves all namespaces.

        Returns:
            list: A list containing all namespace names.
        """
        try:
            v1 = client.CoreV1Api()
            namespace_list = v1.list_namespace()
            namespaces = [item.metadata.name for item in namespace_list.items]
            return namespaces
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def get_pod_current_namespace(self):
        """
        Retrieves the current namespace from the pod's mounted service account info.

        Returns:
            str: The current namespace.
        """
        try:
            with open(
                "/var/run/secrets/kubernetes.io/serviceaccount/namespace", "r"
            ) as f:
                return f.read().strip()
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def print_credentials(self):
        """
        Prints the Kubernetes credentials.
        """
        if self.context.get("name") == "In-Cluster":
            report = f"""
This report is being generated using the Kubernetes configuration below:

Kubernetes Pod: {Fore.YELLOW}[prowler]{Style.RESET_ALL}  Namespace: {Fore.YELLOW}[{self.get_pod_current_namespace()}]{Style.RESET_ALL}
"""
            print(report)
        else:
            cluster_name = self.context.get("context").get("cluster")
            user_name = self.context.get("context").get("user")
            roles = self.get_context_user_roles()
            roles_str = ", ".join(roles) if roles else "No associated Roles"

            report = f"""
This report is being generated using the Kubernetes configuration below:

Kubernetes Cluster: {Fore.YELLOW}[{cluster_name}]{Style.RESET_ALL}  User: {Fore.YELLOW}[{user_name}]{Style.RESET_ALL}  Namespaces: {Fore.YELLOW}[{', '.join(self.namespaces)}]{Style.RESET_ALL}  Roles: {Fore.YELLOW}[{roles_str}]{Style.RESET_ALL}
"""
            print(report)
