import os
from typing import Union

from colorama import Fore, Style
from kubernetes.client.exceptions import ApiException
from kubernetes.config.config_exception import ConfigException
from requests.exceptions import Timeout
from yaml import parser, safe_load

from kubernetes import client, config
from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider
from prowler.providers.kubernetes.exceptions.exceptions import (
    KubernetesAPIError,
    KubernetesCloudResourceManagerAPINotUsedError,
    KubernetesError,
    KubernetesInvalidKubeConfigFileError,
    KubernetesInvalidProviderIdError,
    KubernetesSetUpSessionError,
    KubernetesTimeoutError,
)
from prowler.providers.kubernetes.lib.mutelist.mutelist import KubernetesMutelist
from prowler.providers.kubernetes.models import (
    KubernetesIdentityInfo,
    KubernetesSession,
)


class KubernetesProvider(Provider):
    """
    Represents the Kubernetes provider.

    Attributes:
        _type (str): The provider type, wich is 'kubernetes'.
        _session (KubernetesSession): The Kubernetes session.
        _namespaces (list): The list of namespaces to audit.
        _audit_config (dict): The audit configuration.
        _identity (KubernetesIdentityInfo): The Kubernetes identity information.
        _mutelist (dict): The mutelist.
        audit_metadata (Audit_Metadata): The audit metadata.

    Methods:
        setup_session: Sets up the Kubernetes session.
        test_connection: Tests the connection to the Kubernetes cluster.
        search_and_save_roles: Searches for and saves roles.
        get_context_user_roles: Retrieves the context user roles.
        get_all_namespaces: Retrieves all namespaces.
        get_pod_current_namespace: Retrieves the current namespace from the pod's mounted service account info.
        print_credentials: Prints the Kubernetes credentials.
    """

    _type: str = "kubernetes"
    _session: KubernetesSession
    _namespaces: list
    _audit_config: dict
    _identity: KubernetesIdentityInfo
    _mutelist: dict
    # TODO: this is not optional, enforce for all providers
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        kubeconfig_file: str = None,
        context: str = None,
        namespace: list = None,
        config_path: str = None,
        config_content: dict = {},
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = {},
        kubeconfig_content: Union[dict, str] = None,
    ):
        """
        Initializes the KubernetesProvider instance.

        Args:
            kubeconfig_file (str): Path to the kubeconfig file.
            kubeconfig_content (str or dict): Content of the kubeconfig file.
            context (str): Context name.
            namespace (list): List of namespaces.
            config_content (dict): Audit configuration.
            config_path (str): Path to the configuration file.
            fixer_config (dict): Fixer configuration.
            mutelist_path (str): Path to the mutelist file.
            mutelist_content (dict): Mutelist content.

        Raises:
            KubernetesCloudResourceManagerAPINotUsedError: If the Kubernetes Cloud Resource Manager API is not used.
            KubernetesError: If an error occurs.

        Returns:
            KubernetesProvider: The KubernetesProvider instance.

        Usage:
            - Authentication: The provider can be instantiated in two ways:
                1. Using the kubeconfig file.
                    >>> provider = KubernetesProvider(
                    ...     kubeconfig_file="~/.kube/config",
                    ...     context="my-context",
                    ...     namespace=["default"],
                    ... )
                2. Using the kubeconfig content.
                    >>> provider = KubernetesProvider(
                    ...     kubeconfig_content={"kubecofig": "content"},
                    ...     context="my-context",
                    ...     namespace=["default"],
                    ... )
            - Namespace and context: The provider can be instantiated with or without specifying the namespace and context.
                - Without specifying the namespace:
                    >>> provider = KubernetesProvider(
                    ...     kubeconfig_file="~/.kube/config",
                    ...     context="my-context",
                    ... )
                - With specifying the namespace:
                    >>> provider = KubernetesProvider(
                    ...     kubeconfig_file="~/.kube/config",
                    ...     context="my-context",
                    ...     namespace=["default"],
                    ... )
                - With specifying the context:
                    >>> provider = KubernetesProvider(
                    ...     kubeconfig_file="~/.kube/config",
                    ...     context="my-context",
                    ...     namespace=["default"],
                    ... )
            - Configuration: The provider can be instantiated with or without specifying the configuration.
                - Without specifying the configuration:
                    >>> provider = KubernetesProvider(
                    ...     kubeconfig_file="~/.kube/config",
                    ...     context="my-context",
                    ...     namespace=["default"],
                    ... )
                - With specifying the configuration:
                    >>> provider = KubernetesProvider(
                    ...     kubeconfig_file="~/.kube/config",
                    ...     context="my-context",
                    ...     namespace=["default"],
                    ...     config_path="path/to/config.yaml",
                    ... )
        """

        logger.info("Instantiating Kubernetes Provider ...")
        self._session = self.setup_session(kubeconfig_file, kubeconfig_content, context)
        if not namespace:
            logger.info("Retrieving all namespaces ...")
            self._namespaces = self.get_all_namespaces()
        else:
            self._namespaces = namespace

        if not self._session.api_client:
            logger.critical("Failed to set up a Kubernetes session.")
            raise KubernetesCloudResourceManagerAPINotUsedError(
                message="Failed to set up a Kubernetes session."
            )

        self._identity = KubernetesIdentityInfo(
            context=self._session.context["name"],
            user=self._session.context["context"]["user"],
            cluster=self._session.context["context"]["cluster"],
        )

        # Audit Config
        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        # Fixer Config
        self._fixer_config = fixer_config

        # Mutelist
        if mutelist_content:
            self._mutelist = KubernetesMutelist(
                mutelist_content=mutelist_content,
            )
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = KubernetesMutelist(
                mutelist_path=mutelist_path,
            )

        Provider.set_global_provider(self)

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
    def fixer_config(self):
        return self._fixer_config

    @property
    def mutelist(self) -> KubernetesMutelist:
        """
        mutelist method returns the provider's mutelist.
        """
        return self._mutelist

    @staticmethod
    def setup_session(
        kubeconfig_file: str = None,
        kubeconfig_content: Union[dict, str] = None,
        context: str = None,
    ) -> KubernetesSession:
        """
        Sets up the Kubernetes session.

        Args:
            kubeconfig_file (str): Path to the kubeconfig file.
            kubeconfig_content (str or dict): Content of the kubeconfig file.
            context (str): Context name.

        Returns:
            Tuple: A tuple containing the API client and the context.

        Raises:
            KubernetesInvalidKubeConfigFileError: If the kubeconfig file is invalid.
            KubernetesInvalidProviderIdError: If the provider ID is invalid.
            KubernetesSetUpSessionError: If an error occurs while setting up the session.
        """
        try:
            if kubeconfig_content:
                logger.info("Using kubeconfig content...")
                config_data = safe_load(kubeconfig_content)
                config.load_kube_config_from_dict(config_data, context=context)
                if context:
                    contexts = config_data.get("contexts", [])
                    for context_item in contexts:
                        if context_item["name"] == context:
                            context = context_item
                else:
                    context = config_data.get("contexts", [])[0]
            else:
                logger.info(f"Using kubeconfig file: {kubeconfig_file}...")
                kubeconfig_file = (
                    kubeconfig_file if kubeconfig_file else "~/.kube/config"
                )
                try:
                    config.load_kube_config(
                        config_file=kubeconfig_file,
                        context=context,
                    )
                except ConfigException:
                    # If the kubeconfig file is not found, try to use the in-cluster config
                    logger.info("Using in-cluster config")
                    config.load_incluster_config()
                    context = {
                        "name": "In-Cluster",
                        "context": {
                            "cluster": "in-cluster",  # Placeholder, as the real cluster name is not available
                            "user": "service-account-name",  # Also a placeholder
                        },
                    }
                    return KubernetesSession(
                        api_client=client.ApiClient(), context=context
                    )
                if context:
                    contexts = config.list_kube_config_contexts(
                        config_file=kubeconfig_file
                    )[0]
                    for context_item in contexts:
                        if context_item["name"] == context:
                            context = context_item
                else:
                    # If no context is provided, use the active context in the kubeconfig file
                    # The first element is the list of contexts, the second is the active context
                    context = config.list_kube_config_contexts(
                        config_file=kubeconfig_file
                    )[1]
            return KubernetesSession(api_client=client.ApiClient(), context=context)

        except parser.ParserError as parser_error:
            logger.critical(
                f"{parser_error.__class__.__name__}[{parser_error.__traceback__.tb_lineno}]: {parser_error}"
            )
            raise KubernetesInvalidKubeConfigFileError(
                original_exception=parser_error, file=os.path.abspath(__file__)
            )
        except ConfigException as config_error:
            logger.critical(
                f"{config_error.__class__.__name__}[{config_error.__traceback__.tb_lineno}]: {config_error}"
            )
            if f"Expected object with name {context} in kube-config/contexts" in str(
                config_error
            ):
                raise KubernetesInvalidProviderIdError(
                    original_exception=config_error, file=os.path.abspath(__file__)
                )
            else:
                raise KubernetesInvalidKubeConfigFileError(
                    original_exception=config_error, file=os.path.abspath(__file__)
                )
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise KubernetesSetUpSessionError(
                original_exception=error, file=os.path.abspath(__file__)
            )

    @staticmethod
    def test_connection(
        kubeconfig_file: str = "~/.kube/config",
        kubeconfig_content: Union[dict, str] = None,
        namespace: str = None,
        provider_id: str = None,
        raise_on_exception: bool = True,
    ) -> Connection:
        """
        Tests the connection to the Kubernetes cluster.

        Args:
            kubeconfig_file (str): Path to the kubeconfig file.
            kubeconfig_content (str or dict): Content of the kubeconfig file.
            namespace (str): Namespace name.
            provider_id (str): Provider ID to use, in this case, the Kubernetes context.
            raise_on_exception (bool): Whether to raise an exception on error.

        Returns:
            Connection: A Connection object.

        Raises:
            KubernetesInvalidKubeConfigFileError: If the kubeconfig file is invalid.
            KubernetesInvalidProviderIdError: If the provider ID is invalid.
            KubernetesSetUpSessionError: If an error occurs while setting up the session.
            KubernetesAPIError: If an error occurs while testing the connection.

        Usage:
            - Using the kubeconfig file:
                >>> connection = KubernetesProvider.test_connection(
                ...     kubeconfig_file="~/.kube/config",
                ...     namespace="default",
                ...     provider_id="my-context",
                ...     raise_on_exception=True,
                ... )
            - Using the kubeconfig content:
                >>> connection = KubernetesProvider.test_connection(
                ...     kubeconfig_content="kubeconfig content",
                ...     namespace="default",
                ...     provider_id="my-context",
                ...     raise_on_exception=True,
                ... )
            - Using the namespace:
                >>> connection = KubernetesProvider.test_connection(
                ...     kubeconfig_file="~/.kube/config",
                ...     namespace="default",
                ...     provider_id="my-context",
                ...     raise_on_exception=True,
                ... )
            - Without raising an exception:
                >>> connection = KubernetesProvider.test_connection(
                ...     kubeconfig_file="~/.kube/config",
                ...     namespace="default",
                ...     provider_id="my-context",
                ...     raise_on_exception=False,
                ... )
        """
        try:
            KubernetesProvider.setup_session(
                kubeconfig_file=kubeconfig_file,
                kubeconfig_content=kubeconfig_content,
                context=provider_id,
            )
            if namespace:
                client.CoreV1Api().list_namespaced_pod(
                    namespace, timeout_seconds=2, _request_timeout=2
                )
            else:
                client.CoreV1Api().list_namespace(timeout_seconds=2, _request_timeout=2)
            return Connection(is_connected=True)
        except KubernetesInvalidKubeConfigFileError as invalid_kubeconfig_error:
            logger.critical(
                f"KubernetesInvalidKubeConfigFileError[{invalid_kubeconfig_error.__traceback__.tb_lineno}]: {invalid_kubeconfig_error}"
            )
            if raise_on_exception:
                raise invalid_kubeconfig_error
            return Connection(error=invalid_kubeconfig_error)
        except KubernetesInvalidProviderIdError as invalid_provider_id_error:
            logger.critical(
                f"KubernetesInvalidProviderIdError[{invalid_provider_id_error.__traceback__.tb_lineno}]: {invalid_provider_id_error}"
            )
            if raise_on_exception:
                raise invalid_provider_id_error
            return Connection(error=invalid_provider_id_error)
        except KubernetesSetUpSessionError as setup_session_error:
            logger.critical(
                f"KubernetesSetUpSessionError[{setup_session_error.__traceback__.tb_lineno}]: {setup_session_error}"
            )
            if raise_on_exception:
                raise setup_session_error
            return Connection(error=setup_session_error)
        except ApiException as api_error:
            logger.critical(
                f"ApiException[{api_error.__traceback__.tb_lineno}]: {api_error}"
            )
            if raise_on_exception:
                raise KubernetesAPIError(original_exception=api_error)
            return Connection(error=api_error)
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise KubernetesSetUpSessionError(original_exception=error)
            return Connection(error=error)

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

        Raises:
            KubernetesError: If an error occurs.

        Usage:
            >>> roles = self.search_and_save_roles(
            ...     roles=[],
            ...     role_bindings=rbac_api.list_cluster_role_binding().items,
            ...     context_user="my-user",
            ...     role_binding_type="ClusterRole",
            ... )
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
            raise KubernetesError(
                original_exception=error, file=os.path.abspath(__file__)
            )

    def get_context_user_roles(self):
        """
        Retrieves the context user roles.

        Returns:
            list: A list containing the context user roles.

        Raises:
            KubernetesError: If an error occurs.

        Usage:
            >>> roles = self.get_context_user_roles()
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
        except ApiException as api_error:
            logger.error(
                f"ApiException[{api_error.__traceback__.tb_lineno}]: {api_error}"
            )
        except KubernetesError as error:
            raise error
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def get_all_namespaces(self) -> list[str]:
        """
        Retrieves all namespaces.

        Returns:
            list: A list containing all namespace names.

        Raises:
            KubernetesAPIError: If an error occurs while retrieving the namespaces.
            KubernetesTimeoutError: If a timeout occurs while retrieving the namespaces.
            KubernetesError: If an error occurs.

        Usage:
            >>> namespaces = self.get_all_namespaces()
        """
        try:
            v1 = client.CoreV1Api()
            namespace_list = v1.list_namespace(timeout_seconds=2, _request_timeout=2)
            namespaces = [item.metadata.name for item in namespace_list.items]
            logger.info("All namespaces retrieved successfully.")
            return namespaces
        except ApiException as api_error:
            logger.critical(
                f"ApiException[{api_error.__traceback__.tb_lineno}]: {api_error}"
            )
            raise KubernetesAPIError(
                original_exception=api_error, file=os.path.abspath(__file__)
            )
        except Timeout as timeout_error:
            logger.critical(
                f"Timeout[{timeout_error.__traceback__.tb_lineno}]: {timeout_error}"
            )
            raise KubernetesTimeoutError(
                original_exception=timeout_error, file=os.path.abspath(__file__)
            )
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise KubernetesError(
                original_exception=error, file=os.path.abspath(__file__)
            )

    def get_pod_current_namespace(self):
        """
        Retrieves the current namespace from the pod's mounted service account info.

        Returns:
            str: The current namespace.

        Usage:
            >>> namespace = self.get_pod_current_namespace()
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

        Usage:
            >>> self.print_credentials()
        """
        if self._identity.context == "In-Cluster":
            report_lines = [
                f"Kubernetes Pod: {Fore.YELLOW}prowler{Style.RESET_ALL}",
                f"Namespace: {Fore.YELLOW}{self.get_pod_current_namespace()}{Style.RESET_ALL}",
            ]
        else:
            roles = self.get_context_user_roles()
            roles_str = ", ".join(roles) if roles else "No associated Roles"
            report_lines = [
                f"Kubernetes Cluster: {Fore.YELLOW}{self._identity.cluster}{Style.RESET_ALL}",
                f"User: {Fore.YELLOW}{self._identity.user}{Style.RESET_ALL}",
                f"Namespaces: {Fore.YELLOW}{', '.join(self.namespaces)}{Style.RESET_ALL}",
                f"Roles: {Fore.YELLOW}{roles_str}{Style.RESET_ALL}",
            ]
        report_title = (
            f"{Style.BRIGHT}Using the Kubernetes credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)
