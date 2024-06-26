from argparse import Namespace
from os import rmdir
from unittest.mock import patch

from kubernetes import client
from prowler.config.config import (
    default_config_file_path,
    default_fixer_config_file_path,
)
from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider
from prowler.providers.kubernetes.models import (
    KubernetesIdentityInfo,
    KubernetesOutputOptions,
    KubernetesSession,
)
from tests.providers.kubernetes.kubernetes_fixtures import KUBERNETES_CONFIG


def mock_set_kubernetes_credentials(*_):
    return ("apiclient", "context")


def mock_get_context_user_roles(*_):
    return []


class TestKubernetesProvider:
    def test_kubernetes_provider_no_namespaces(
        self,
    ):
        context = {
            "name": "test-context",
            "context": {
                "user": "test-user",
                "cluster": "test-cluster",
            },
        }
        with patch(
            "prowler.providers.kubernetes.kubernetes_provider.KubernetesProvider.setup_session",
            return_value=KubernetesSession(
                api_client=client.ApiClient,
                context=context,
            ),
        ), patch(
            "prowler.providers.kubernetes.kubernetes_provider.KubernetesProvider.get_all_namespaces",
            return_value=["namespace-1"],
        ):
            arguments = Namespace()
            arguments.kubeconfig_file = "dummy_path"
            arguments.context = None
            arguments.only_logs = False
            arguments.namespace = None
            arguments.config_file = default_config_file_path
            arguments.fixer_config = default_fixer_config_file_path

            # Instantiate the KubernetesProvider with mocked arguments
            kubernetes_provider = KubernetesProvider(arguments)
            print(kubernetes_provider.__dict__)
            assert isinstance(kubernetes_provider.session, KubernetesSession)
            assert kubernetes_provider.session.api_client is not None
            assert kubernetes_provider.session.context == {
                "name": "test-context",
                "context": {"cluster": "test-cluster", "user": "test-user"},
            }
            assert kubernetes_provider.namespaces == ["namespace-1"]
            assert isinstance(kubernetes_provider.identity, KubernetesIdentityInfo)
            assert kubernetes_provider.identity.context == "test-context"
            assert kubernetes_provider.identity.cluster == "test-cluster"
            assert kubernetes_provider.identity.user == "test-user"

            assert kubernetes_provider.audit_config == KUBERNETES_CONFIG

    def test_set_provider_output_options_kubernetes(self):
        arguments = Namespace()
        arguments.kubeconfig_file = "dummy_path"
        arguments.context = None
        arguments.only_logs = False
        arguments.namespace = None
        arguments.config_file = default_config_file_path
        arguments.fixer_config = default_fixer_config_file_path
        arguments.status = []
        arguments.output_formats = ["csv"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.output_filename = "output_test_filename"
        arguments.only_logs = False
        arguments.unix_timestamp = False
        arguments.shodan = "test-api-key"

        context = {
            "name": "test-context",
            "context": {
                "user": "test-user",
                "cluster": "test-cluster",
            },
        }
        with patch(
            "prowler.providers.kubernetes.kubernetes_provider.KubernetesProvider.setup_session",
            return_value=KubernetesSession(
                api_client=client.ApiClient,
                context=context,
            ),
        ), patch(
            "prowler.providers.kubernetes.kubernetes_provider.KubernetesProvider.get_all_namespaces",
            return_value=["namespace-1"],
        ):

            kubernetes_provider = KubernetesProvider(arguments)
            # This is needed since the output_options requires to get the global provider to get the audit config
            with patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=kubernetes_provider,
            ):

                kubernetes_provider.output_options = arguments, {}

                assert isinstance(
                    kubernetes_provider.output_options, KubernetesOutputOptions
                )
                assert kubernetes_provider.output_options.status == []
                assert kubernetes_provider.output_options.output_modes == ["csv"]
                assert (
                    kubernetes_provider.output_options.output_directory
                    == arguments.output_directory
                )
                assert kubernetes_provider.output_options.bulk_checks_metadata == {}
                assert kubernetes_provider.output_options.verbose
                assert (
                    kubernetes_provider.output_options.output_filename
                    == arguments.output_filename
                )

                # Delete testing directory
                rmdir(f"{arguments.output_directory}/compliance")
                rmdir(arguments.output_directory)

    # @patch("kubernetes.client.RbacAuthorizationV1Api")
    # @patch("kubernetes.config.list_kube_config_contexts")
    # @patch("kubernetes.config.load_incluster_config")
    # @patch("kubernetes.config.load_kube_config")
    # def test_get_context_user_roles(
    #     self,
    #     mock_list_kube_config_contexts,
    #     mock_rbac_api,
    # ):
    #     mock_list_kube_config_contexts.return_value = (
    #         [
    #             {
    #                 "name": "context_name",
    #                 "context": {"cluster": "test-cluster", "user": "test-user"},
    #             }
    #         ],
    #         0,
    #     )

    #     # Mock the RbacAuthorizationV1Api methods
    #     cluster_role_binding = MagicMock()
    #     role_binding = MagicMock()
    #     cluster_role_binding.list_cluster_role_binding.return_value = MagicMock(
    #         items=[]
    #     )
    #     role_binding.list_role_binding_for_all_namespaces.return_value = MagicMock(
    #         items=[]
    #     )

    #     mock_rbac_api.return_value = MagicMock(
    #         list_cluster_role_binding=cluster_role_binding.list_cluster_role_binding,
    #         list_role_binding_for_all_namespaces=role_binding.list_role_binding_for_all_namespaces,
    #     )

    #     args = Namespace(kubeconfig_file=None, context=None, only_logs=False)
    #     provider = KubernetesProvider(args)

    #     roles = provider.get_context_user_roles()

    #     assert isinstance(roles, list)

    # @patch("kubernetes.client.RbacAuthorizationV1Api")
    # @patch("kubernetes.client.ApiClient")
    # @patch("kubernetes.config.load_kube_config")
    # @patch("kubernetes.config.load_incluster_config")
    # @patch("kubernetes.config.list_kube_config_contexts")
    # @patch("sys.stdout", new_callable=MagicMock)
    # def test_print_credentials(
    #     self,
    #     mock_list_kube_config_contexts,
    # ):
    #     mock_list_kube_config_contexts.return_value = (
    #         [
    #             {
    #                 "name": "context_name",
    #                 "context": {"cluster": "test-cluster", "user": "test-user"},
    #             }
    #         ],
    #         0,
    #     )

    #     args = Namespace(kubeconfig_file=None, context=None, only_logs=False)
    #     provider = KubernetesProvider(args)
    #     provider.context = {
    #         "context": {"cluster": "test-cluster", "user": "test-user"},
    #         "namespace": "default",
    #     }
    #     provider.get_context_user_roles = MagicMock(return_value=["ClusterRole: admin"])

    #     # Capture print output
    #     captured_output = io.StringIO()
    #     sys.stdout = captured_output

    #     provider.print_credentials()

    #     # Reset standard output
    #     sys.stdout = sys.__stdout__

    #     output = captured_output.getvalue()
    #     assert "[test-cluster]" in output
    #     assert "[test-user]" in output
    #     assert "[default]" in output
    #     assert "[ClusterRole: admin]" in output

    # @patch("kubernetes.client.RbacAuthorizationV1Api")
    # @patch("kubernetes.config.list_kube_config_contexts")
    # @patch("kubernetes.config.load_incluster_config")
    # @patch("kubernetes.config.load_kube_config")
    # def test_search_and_save_roles(
    #     self,
    #     mock_list_kube_config_contexts,
    #     mock_rbac_api,
    # ):
    #     mock_list_kube_config_contexts.return_value = (
    #         [
    #             {
    #                 "name": "context_name",
    #                 "context": {"cluster": "test-cluster", "user": "test-user"},
    #             }
    #         ],
    #         0,
    #     )
    #     mock_rbac_api.return_value.list_cluster_role_binding.return_value = MagicMock(
    #         items=[]
    #     )
    #     mock_rbac_api.return_value.list_role_binding_for_all_namespaces.return_value = (
    #         MagicMock(items=[])
    #     )

    #     args = Namespace(kubeconfig_file=None, context=None, only_logs=False)
    #     provider = KubernetesProvider(args)
    #     provider.context = {"context": {"user": "test-user"}}

    #     roles = provider.search_and_save_roles([], [], "test-user", "ClusterRole")
    #     assert isinstance(roles, list)
