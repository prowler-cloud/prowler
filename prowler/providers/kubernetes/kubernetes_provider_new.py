import os
import sys
from argparse import Namespace
from typing import Any, Optional

from colorama import Fore, Style
from kubernetes import client, config

from prowler.lib.logger import logger
from prowler.providers.common.provider import Provider


class KubernetesProvider(Provider):
    # TODO change class name from Provider to Provider
    api_client: Any
    context: dict
    audit_resources: Optional[Any]
    audit_metadata: Optional[Any]
    audit_config: Optional[dict]

    def __init__(self, arguments: Namespace):
        logger.info("Instantiating Kubernetes Provider ...")
        self.api_client, self.context = self.setup_session(
            arguments.kubeconfig_file, arguments.context
        )

        if not self.api_client:
            logger.critical("Failed to set up a Kubernetes session.")
            sys.exit(1)
        if not arguments.only_logs:
            self.print_credentials()

    def setup_session(self, kubeconfig_file, context):
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

    def print_credentials(self):

        # Get the current context
        cluster_name = self.context.get("context").get("cluster")
        user_name = self.context.get("context").get("user")
        namespace = self.context.get("namespace", "default")
        roles = self.get_context_user_roles()
        roles_str = ", ".join(roles) if roles else "No associated Roles"

        report = f"""
This report is being generated using the Kubernetes configuration below:

Kubernetes Cluster: {Fore.YELLOW}[{cluster_name}]{Style.RESET_ALL}  User: {Fore.YELLOW}[{user_name}]{Style.RESET_ALL}  Namespace: {Fore.YELLOW}[{namespace}]{Style.RESET_ALL}  Roles: {Fore.YELLOW}[{roles_str}]{Style.RESET_ALL}
"""
        print(report)
