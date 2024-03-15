import os
import sys
from argparse import Namespace

from colorama import Fore, Style
from kubernetes import client, config

from prowler.config.config import load_and_validate_config_file
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import parse_mutelist_file
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider
from prowler.providers.kubernetes.models import (
    KubernetesIdentityInfo,
    KubernetesOutputOptions,
    KubernetesSession,
)


class KubernetesProvider(Provider):
    _type: str = "kubernetes"
    _session: KubernetesSession
    _namespaces: list
    _audit_config: dict
    _identity: KubernetesIdentityInfo
    _output_options: KubernetesOutputOptions
    # TODO: enforce the mutelist for the Provider class
    # _mutelist: dict = {}
    # TODO: this is not optional, enforce for all providers
    audit_metadata: Audit_Metadata

    def __init__(self, arguments: Namespace):
        """
        Initializes the KubernetesProvider instance.
        Args:
            arguments (dict): A dictionary containing configuration arguments.
        """
        logger.info("Instantiating Kubernetes Provider ...")
        self._session = self.setup_session(arguments.kubeconfig_file, arguments.context)
        if not arguments.namespaces:
            logger.info("Retrieving all namespaces ...")
            self._namespaces = self.get_all_namespaces()
        else:
            self._namespaces = arguments.namespaces

        if not self._session.api_client:
            logger.critical("Failed to set up a Kubernetes session.")
            sys.exit(1)

        self._identity = KubernetesIdentityInfo(
            context=self._session.context["name"].replace(":", "_").replace("/", "_"),
            user=self._session.context["context"]["user"],
            cluster=self._session.context["context"]["cluster"],
        )

        # TODO: move this to the providers, pending for AWS, GCP, AZURE and K8s
        # Audit Config
        self._audit_config = load_and_validate_config_file(
            self._type, arguments.config_file
        )

    @property
    def type(self):
        return self._type

    @property
    def session(self):
        return self._session

    @property
    def identity(self):
        return self._identity

    @property
    def namespaces(self):
        return self._namespaces

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def output_options(self):
        return self._output_options

    @output_options.setter
    def output_options(self, options: tuple):
        arguments, bulk_checks_metadata = options
        self._output_options = KubernetesOutputOptions(
            arguments, bulk_checks_metadata, self._identity
        )

    @property
    def get_output_mapping(self):
        return {
            # "in-cluster/kubeconfig"
            # "auth_method": "identity.profile",
            "provider": "type",
            # cluster: <context>
            "account_uid": "identity.cluster",
            # "account_name": "organizations_metadata.account_details_name",
            # "account_email": "organizations_metadata.account_details_email",
            # "account_organization_uid": "organizations_metadata.account_details_arn",
            # "account_organization": "organizations_metadata.account_details_org",
            # "account_tags": "organizations_metadata.account_details_tags",
            # "partition": "identity.partition",
        }

    @property
    def mutelist(self):
        return self._mutelist

    @mutelist.setter
    def mutelist(self, mutelist_path):
        if mutelist_path:
            mutelist = parse_mutelist_file(mutelist_path)
        else:
            mutelist = {}
        self._mutelist = mutelist

    def setup_session(self, kubeconfig_file, input_context) -> KubernetesSession:
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
                        "cluster": "in-cluster",  # Placeholder, as the real cluster name is not available
                        "user": "service-account-name",  # Also a placeholder
                    },
                }
            return KubernetesSession(api_client=client.ApiClient(), context=context)
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
            context_user = self._identity.user
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
            logger.info("Context user roles retrieved successfully.")
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
            namespace_list = v1.list_namespace(timeout_seconds=2, _request_timeout=2)
            namespaces = [item.metadata.name for item in namespace_list.items]
            logger.info("All namespaces retrieved successfully.")
            return namespaces
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            sys.exit()

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
            return "default"

    def print_credentials(self):
        """
        Prints the Kubernetes credentials.
        """
        if self._identity.context == "In-Cluster":
            report = f"""
This report is being generated using the Kubernetes configuration below:

Kubernetes Pod: {Fore.YELLOW}[prowler]{Style.RESET_ALL}  Namespace: {Fore.YELLOW}[{self.get_pod_current_namespace()}]{Style.RESET_ALL}
"""
            print(report)
        else:
            roles = self.get_context_user_roles()
            roles_str = ", ".join(roles) if roles else "No associated Roles"

            report = f"""
This report is being generated using the Kubernetes configuration below:

Kubernetes Cluster: {Fore.YELLOW}[{self._identity.cluster}]{Style.RESET_ALL} User: {Fore.YELLOW}[{self._identity.user}]{Style.RESET_ALL} Namespaces: {Fore.YELLOW}[{', '.join(self.namespaces)}]{Style.RESET_ALL} Roles: {Fore.YELLOW}[{roles_str}]{Style.RESET_ALL}
"""
            print(report)
