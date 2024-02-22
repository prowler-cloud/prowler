import io
import sys
from argparse import Namespace
from unittest.mock import MagicMock, patch

from prowler.providers.kubernetes.kubernetes_provider_new import KubernetesProvider


class TestKubernetesProvider:
    @patch("kubernetes.client.RbacAuthorizationV1Api")
    @patch("kubernetes.client.ApiClient")
    @patch("kubernetes.config.load_kube_config")
    @patch("kubernetes.config.load_incluster_config")
    @patch("kubernetes.config.list_kube_config_contexts")
    def test_setup_session(
        self,
        mock_list_kube_config_contexts,
        mock_load_incluster_config,
        mock_load_kube_config,
        mock_api_client,
        mock_rbac_api,
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
        mock_load_kube_config,
        mock_load_incluster_config,
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
        mock_stdout,
        mock_list_kube_config_contexts,
        mock_load_incluster_config,
        mock_load_kube_config,
        mock_api_client,
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
        mock_load_kube_config,
        mock_load_incluster_config,
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
