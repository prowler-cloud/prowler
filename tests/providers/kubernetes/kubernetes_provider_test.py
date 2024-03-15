import io
import sys
from argparse import Namespace
from unittest.mock import MagicMock, patch

from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider


def mock_set_kubernetes_credentials(*_):
    return ("apiclient", "context")


def mock_get_context_user_roles(*_):
    return []


class TestKubernetesProvider:
    @patch("kubernetes.client.RbacAuthorizationV1Api")
    @patch("kubernetes.client.ApiClient")
    @patch("kubernetes.config.load_kube_config")
    @patch("kubernetes.config.load_incluster_config")
    @patch("kubernetes.config.list_kube_config_contexts")
    def test_setup_session(
        self,
        mock_list_kube_config_contexts,
    ):
        # Mocking the return value of list_kube_config_contexts
        mock_list_kube_config_contexts.return_value = (
            [
                {
                    "name": "context_name",
                    "context": {"cluster": "test-cluster", "user": "test-user"},
                }
            ],
            0,
        )

        # Create a Namespace object for arguments
        args = Namespace(kubeconfig_file="dummy_path", context=None, only_logs=False)

        # Instantiate the KubernetesProvider with mocked arguments
        provider = KubernetesProvider(args)

        # Assert that an ApiClient has been created
        assert provider.api_client is not None

        # Assert that the context has been correctly set
        assert provider.context == {
            "name": "context_name",
            "context": {"cluster": "test-cluster", "user": "test-user"},
        }

    @patch("kubernetes.client.RbacAuthorizationV1Api")
    @patch("kubernetes.config.list_kube_config_contexts")
    @patch("kubernetes.config.load_incluster_config")
    @patch("kubernetes.config.load_kube_config")
    def test_get_context_user_roles(
        self,
        mock_list_kube_config_contexts,
        mock_rbac_api,
    ):
        mock_list_kube_config_contexts.return_value = (
            [
                {
                    "name": "context_name",
                    "context": {"cluster": "test-cluster", "user": "test-user"},
                }
            ],
            0,
        )

        # Mock the RbacAuthorizationV1Api methods
        cluster_role_binding = MagicMock()
        role_binding = MagicMock()
        cluster_role_binding.list_cluster_role_binding.return_value = MagicMock(
            items=[]
        )
        role_binding.list_role_binding_for_all_namespaces.return_value = MagicMock(
            items=[]
        )

        mock_rbac_api.return_value = MagicMock(
            list_cluster_role_binding=cluster_role_binding.list_cluster_role_binding,
            list_role_binding_for_all_namespaces=role_binding.list_role_binding_for_all_namespaces,
        )

        args = Namespace(kubeconfig_file=None, context=None, only_logs=False)
        provider = KubernetesProvider(args)

        roles = provider.get_context_user_roles()

        assert isinstance(roles, list)

    @patch("kubernetes.client.RbacAuthorizationV1Api")
    @patch("kubernetes.client.ApiClient")
    @patch("kubernetes.config.load_kube_config")
    @patch("kubernetes.config.load_incluster_config")
    @patch("kubernetes.config.list_kube_config_contexts")
    @patch("sys.stdout", new_callable=MagicMock)
    def test_print_credentials(
        self,
        mock_list_kube_config_contexts,
    ):
        mock_list_kube_config_contexts.return_value = (
            [
                {
                    "name": "context_name",
                    "context": {"cluster": "test-cluster", "user": "test-user"},
                }
            ],
            0,
        )

        args = Namespace(kubeconfig_file=None, context=None, only_logs=False)
        provider = KubernetesProvider(args)
        provider.context = {
            "context": {"cluster": "test-cluster", "user": "test-user"},
            "namespace": "default",
        }
        provider.get_context_user_roles = MagicMock(return_value=["ClusterRole: admin"])

        # Capture print output
        captured_output = io.StringIO()
        sys.stdout = captured_output

        provider.print_credentials()

        # Reset standard output
        sys.stdout = sys.__stdout__

        output = captured_output.getvalue()
        assert "[test-cluster]" in output
        assert "[test-user]" in output
        assert "[default]" in output
        assert "[ClusterRole: admin]" in output

    @patch("kubernetes.client.RbacAuthorizationV1Api")
    @patch("kubernetes.config.list_kube_config_contexts")
    @patch("kubernetes.config.load_incluster_config")
    @patch("kubernetes.config.load_kube_config")
    def test_search_and_save_roles(
        self,
        mock_list_kube_config_contexts,
        mock_rbac_api,
    ):
        mock_list_kube_config_contexts.return_value = (
            [
                {
                    "name": "context_name",
                    "context": {"cluster": "test-cluster", "user": "test-user"},
                }
            ],
            0,
        )
        mock_rbac_api.return_value.list_cluster_role_binding.return_value = MagicMock(
            items=[]
        )
        mock_rbac_api.return_value.list_role_binding_for_all_namespaces.return_value = (
            MagicMock(items=[])
        )

        args = Namespace(kubeconfig_file=None, context=None, only_logs=False)
        provider = KubernetesProvider(args)
        provider.context = {"context": {"user": "test-user"}}

        roles = provider.search_and_save_roles([], [], "test-user", "ClusterRole")
        assert isinstance(roles, list)

    @patch.object(
        Kubernetes_Provider, "__set_credentials__", new=mock_set_kubernetes_credentials
    )
    @patch.object(
        Kubernetes_Provider, "get_context_user_roles", new=mock_get_context_user_roles
    )
    def test_set_audit_info_kubernetes(self):
        provider = "kubernetes"
        arguments = {
            "profile": None,
            "role": None,
            "session_duration": None,
            "external_id": None,
            "regions": None,
            "organizations_role": None,
            "subscriptions": None,
            "context": "default",
            "kubeconfig_file": "config",
            "config_file": default_config_file_path,
        }

        audit_info = set_provider_audit_info(provider, arguments)
        assert isinstance(audit_info, Kubernetes_Audit_Info)

    def test_set_provider_output_options_kubernetes(self):
        #  Set the cloud provider
        provider = "kubernetes"
        # Set the arguments passed
        arguments = Namespace()
        arguments.quiet = True
        arguments.output_modes = ["csv"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.output_filename = "output_test_filename"
        arguments.only_logs = False
        arguments.unix_timestamp = False

        audit_info = self.set_mocked_kubernetes_audit_info()
        mutelist_file = ""
        bulk_checks_metadata = {}
        output_options = set_provider_output_options(
            provider, arguments, audit_info, mutelist_file, bulk_checks_metadata
        )
        assert isinstance(output_options, Kubernetes_Output_Options)
        assert output_options.is_quiet
        assert output_options.output_modes == ["csv"]
        assert output_options.output_directory == arguments.output_directory
        assert output_options.mutelist_file == ""
        assert output_options.bulk_checks_metadata == {}
        assert output_options.verbose
        assert output_options.output_filename == arguments.output_filename

        # Delete testing directory
        rmdir(arguments.output_directory)
