from argparse import Namespace
from unittest.mock import patch

from kubernetes.config.config_exception import ConfigException

from kubernetes import client
from prowler.config.config import (
    default_config_file_path,
    default_fixer_config_file_path,
    load_and_validate_config_file,
)
from prowler.providers.kubernetes.exceptions.exceptions import (
    KubernetesSetUpSessionError,
)
from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider
from prowler.providers.kubernetes.models import (
    KubernetesIdentityInfo,
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
        with (
            patch(
                "prowler.providers.kubernetes.kubernetes_provider.KubernetesProvider.setup_session",
                return_value=KubernetesSession(
                    api_client=client.ApiClient,
                    context=context,
                ),
            ),
            patch(
                "prowler.providers.kubernetes.kubernetes_provider.KubernetesProvider.get_all_namespaces",
                return_value=["namespace-1"],
            ),
        ):
            arguments = Namespace()
            arguments.kubeconfig_file = "dummy_path"
            arguments.context = None
            arguments.only_logs = False
            arguments.namespace = None
            fixer_config = load_and_validate_config_file(
                "kubernetes", default_fixer_config_file_path
            )

            # Instantiate the KubernetesProvider with mocked arguments
            kubernetes_provider = KubernetesProvider(
                arguments.kubeconfig_file,
                arguments.context,
                arguments.namespace,
                config_path=default_config_file_path,
                fixer_config=fixer_config,
            )
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

    @patch(
        "prowler.providers.kubernetes.kubernetes_provider.client.CoreV1Api.list_namespace"
    )
    @patch("kubernetes.config.list_kube_config_contexts")
    @patch("kubernetes.config.load_kube_config_from_dict")
    def test_kubernetes_test_connection_with_kubeconfig_content(
        self,
        mock_load_kube_config_from_dict,
        mock_list_kube_config_contexts,
        mock_list_namespace,
    ):
        mock_load_kube_config_from_dict.return_value = None
        mock_list_kube_config_contexts.return_value = (
            [
                {
                    "name": "example-context",
                    "context": {
                        "cluster": "example-cluster",
                        "user": "example-user",
                    },
                }
            ],
            None,
        )
        mock_list_namespace.return_value.items = [
            client.V1Namespace(metadata=client.V1ObjectMeta(name="namespace-1")),
        ]

        kubeconfig_content = '{"apiVersion": "v1", "clusters": [{"cluster": {"server": "https://kubernetes.example.com"}, "name": "example-cluster"}], "contexts": [{"context": {"cluster": "example-cluster", "user": "example-user"}, "name": "example-context"}], "current-context": "example-context", "kind": "Config", "preferences": {}, "users": [{"name": "example-user", "user": {"token": "EXAMPLE_TOKEN"}}]}'

        connection = KubernetesProvider.test_connection(
            kubeconfig_file=None,
            kubeconfig_content=kubeconfig_content,
            provider_id="example-context",
            raise_on_exception=False,
        )

        assert connection.is_connected
        assert connection.error is None

    @patch(
        "prowler.providers.kubernetes.kubernetes_provider.client.CoreV1Api.list_namespace"
    )
    @patch("kubernetes.config.list_kube_config_contexts")
    @patch("kubernetes.config.load_kube_config")
    def test_kubernetes_test_connection_with_kubeconfig_file(
        self, mock_load_kube_config, mock_list_kube_config_contexts, mock_list_namespace
    ):
        mock_load_kube_config.return_value = None
        mock_list_kube_config_contexts.return_value = (
            [
                {
                    "name": "test-context",
                    "context": {
                        "cluster": "test-cluster",
                        "user": "test-user",
                    },
                }
            ],
            None,
        )
        mock_list_namespace.return_value.items = [
            client.V1Namespace(metadata=client.V1ObjectMeta(name="namespace-1")),
        ]

        connection = KubernetesProvider.test_connection(
            kubeconfig_file="dummy_kubeconfig_path",
            kubeconfig_content="",
            provider_id="test-context",
            raise_on_exception=False,
        )

        assert connection.is_connected
        assert connection.error is None

    @patch(
        "prowler.providers.kubernetes.kubernetes_provider.client.CoreV1Api.list_namespaced_pod"
    )
    @patch("kubernetes.config.list_kube_config_contexts")
    @patch("kubernetes.config.load_kube_config")
    def test_kubernetes_test_connection_with_namespace_input(
        self,
        mock_load_kube_config,
        mock_list_kube_config_contexts,
        mock_list_namespaced_pod,
    ):
        mock_load_kube_config.return_value = None
        mock_list_kube_config_contexts.return_value = (
            [
                {
                    "name": "test-context",
                    "context": {
                        "cluster": "test-cluster",
                        "user": "test-user",
                    },
                }
            ],
            None,
        )
        mock_list_namespaced_pod.return_value.items = [
            client.V1Pod(metadata=client.V1ObjectMeta(name="pod-1")),
        ]

        connection = KubernetesProvider.test_connection(
            kubeconfig_file="",
            kubeconfig_content="",
            namespace="test-namespace",
            provider_id="test-context",
            raise_on_exception=False,
        )

        assert connection.is_connected
        assert connection.error is None

    @patch(
        "prowler.providers.kubernetes.kubernetes_provider.client.CoreV1Api.list_namespace"
    )
    @patch("kubernetes.config.list_kube_config_contexts")
    @patch("kubernetes.config.load_kube_config_from_dict")
    def test_kubernetes_test_connection_with_kubeconfig_content_invalid_provider_id(
        self,
        mock_load_kube_config_from_dict,
        mock_list_kube_config_contexts,
        mock_list_namespace,
    ):
        mock_load_kube_config_from_dict.return_value = None
        mock_list_kube_config_contexts.return_value = (
            [
                {
                    "name": "example-context",
                    "context": {
                        "cluster": "example-cluster",
                        "user": "example-user",
                    },
                }
            ],
            None,
        )
        mock_list_namespace.return_value.items = [
            client.V1Namespace(metadata=client.V1ObjectMeta(name="namespace-1")),
        ]

        kubeconfig_content = {
            "apiVersion": "v1",
            "clusters": [
                {
                    "cluster": {
                        "server": "https://kubernetes.example.com",
                    },
                    "name": "example-cluster",
                }
            ],
            "contexts": [
                {
                    "context": {
                        "cluster": "example-cluster",
                        "user": "example-user",
                    },
                    "name": "example-context",
                }
            ],
            "current-context": "example-context",
            "kind": "Config",
            "preferences": {},
            "users": [
                {
                    "name": "example-user",
                    "user": {
                        "token": "EXAMPLE_TOKEN",
                    },
                }
            ],
        }

        connection = KubernetesProvider.test_connection(
            kubeconfig_file=None,
            kubeconfig_content=kubeconfig_content,
            provider_id="example-context-invalid",
            raise_on_exception=False,
        )

        assert not connection.is_connected
        assert connection.error is not None
        assert isinstance(connection.error, KubernetesSetUpSessionError)

    @patch(
        "prowler.providers.kubernetes.kubernetes_provider.client.CoreV1Api.list_namespace"
    )
    @patch("kubernetes.config.list_kube_config_contexts")
    @patch("kubernetes.config.load_kube_config_from_dict")
    def test_kubernetes_test_connection_with_kubeconfig_content_valid_provider_id(
        self,
        mock_load_kube_config_from_dict,
        mock_list_kube_config_contexts,
        mock_list_namespace,
    ):
        mock_load_kube_config_from_dict.return_value = None
        mock_list_kube_config_contexts.return_value = (
            [
                {
                    "name": "example-context",
                    "context": {
                        "cluster": "example-cluster",
                        "user": "example-user",
                    },
                }
            ],
            None,
        )
        mock_list_namespace.return_value.items = [
            client.V1Namespace(metadata=client.V1ObjectMeta(name="namespace-1")),
        ]

        kubeconfig_content = '{"apiVersion": "v1", "clusters": [{"cluster": {"server": "https://kubernetes.example.com"}, "name": "example-cluster"}], "contexts": [{"context": {"cluster": "example-cluster", "user": "example-user"}, "name": "example-context"}], "current-context": "example-context", "kind": "Config", "preferences": {}, "users": [{"name": "example-user", "user": {"token": "EXAMPLE_TOKEN"}}]}'

        connection = KubernetesProvider.test_connection(
            kubeconfig_file=None,
            kubeconfig_content=kubeconfig_content,
            provider_id="example-context",
            raise_on_exception=False,
        )

        assert connection.is_connected
        assert connection.error is None

    def test_kubernetes_provider_incluster_with_env_var(self, monkeypatch):
        monkeypatch.setenv("CLUSTER_NAME", "env-cluster-name")

        with (
            patch(
                "kubernetes.config.load_kube_config",
                side_effect=ConfigException("No kubeconfig"),
            ),
            patch("kubernetes.config.load_incluster_config", return_value=None),
            patch("prowler.providers.kubernetes.kubernetes_provider.client.ApiClient"),
            patch(
                "prowler.providers.kubernetes.kubernetes_provider.KubernetesProvider.get_all_namespaces",
                return_value=["default"],
            ),
        ):
            session = KubernetesProvider.setup_session(
                kubeconfig_file=None,
                kubeconfig_content=None,
                context=None,
                cluster_name=None,
            )
            assert isinstance(session, KubernetesSession)
            assert session.context["context"]["cluster"] == "env-cluster-name"

    def test_kubernetes_provider_incluster_with_cli_flag(self):
        with (
            patch(
                "kubernetes.config.load_kube_config",
                side_effect=ConfigException("No kubeconfig"),
            ),
            patch("kubernetes.config.load_incluster_config", return_value=None),
            patch("prowler.providers.kubernetes.kubernetes_provider.client.ApiClient"),
            patch(
                "prowler.providers.kubernetes.kubernetes_provider.KubernetesProvider.get_all_namespaces",
                return_value=["default"],
            ),
        ):
            session = KubernetesProvider.setup_session(
                kubeconfig_file=None,
                kubeconfig_content=None,
                context=None,
                cluster_name="cli-cluster-name",
            )
            assert isinstance(session, KubernetesSession)
            assert session.context["context"]["cluster"] == "cli-cluster-name"

    @patch(
        "prowler.providers.kubernetes.kubernetes_provider.client.CoreV1Api.list_namespace"
    )
    @patch("kubernetes.config.list_kube_config_contexts")
    @patch("kubernetes.config.load_kube_config_from_dict")
    def test_kubernetes_provider_proxy_from_env(
        self,
        mock_load_kube_config_from_dict,
        mock_list_kube_config_contexts,
        mock_list_namespace,
        monkeypatch,
    ):

        monkeypatch.setenv("HTTPS_PROXY", "http://my.internal.proxy:8888")

        mock_load_kube_config_from_dict.return_value = None
        mock_list_kube_config_contexts.return_value = (
            [
                {
                    "name": "example-context",
                    "context": {
                        "cluster": "example-cluster",
                        "user": "example-user",
                    },
                }
            ],
            None,
        )
        mock_list_namespace.return_value.items = [
            client.V1Namespace(metadata=client.V1ObjectMeta(name="namespace-1")),
        ]

        kubeconfig_content = '{"apiVersion": "v1", "clusters": [{"cluster": {"server": "https://kubernetes.example.com"}, "name": "example-cluster"}], "contexts": [{"context": {"cluster": "example-cluster", "user": "example-user"}, "name": "example-context"}], "current-context": "example-context", "kind": "Config", "preferences": {}, "users": [{"name": "example-user", "user": {"token": "EXAMPLE_TOKEN"}}]}'

        session = KubernetesProvider.setup_session(
            kubeconfig_content=kubeconfig_content,
            context="example-context",
        )

        assert isinstance(session, KubernetesSession)
        assert isinstance(session.api_client, client.ApiClient)
        assert isinstance(session.api_client.configuration, client.Configuration)
        assert session.api_client.configuration.verify_ssl
        assert session.api_client.configuration.proxy == "http://my.internal.proxy:8888"

    @patch(
        "prowler.providers.kubernetes.kubernetes_provider.client.CoreV1Api.list_namespace"
    )
    @patch("kubernetes.config.list_kube_config_contexts")
    @patch("kubernetes.config.load_kube_config_from_dict")
    def test_kubernetes_provider_disable_tls_verification(
        self,
        mock_load_kube_config_from_dict,
        mock_list_kube_config_contexts,
        mock_list_namespace,
        monkeypatch,
    ):
        monkeypatch.setenv("K8S_SKIP_TLS_VERIFY", "true")

        mock_load_kube_config_from_dict.return_value = None
        mock_list_kube_config_contexts.return_value = (
            [
                {
                    "name": "example-context",
                    "context": {
                        "cluster": "example-cluster",
                        "user": "example-user",
                    },
                }
            ],
            None,
        )
        mock_list_namespace.return_value.items = [
            client.V1Namespace(metadata=client.V1ObjectMeta(name="namespace-1")),
        ]

        kubeconfig_content = '{"apiVersion": "v1", "clusters": [{"cluster": {"server": "https://kubernetes.example.com"}, "name": "example-cluster"}], "contexts": [{"context": {"cluster": "example-cluster", "user": "example-user"}, "name": "example-context"}], "current-context": "example-context", "kind": "Config", "preferences": {}, "users": [{"name": "example-user", "user": {"token": "EXAMPLE_TOKEN"}}]}'

        session = KubernetesProvider.setup_session(
            kubeconfig_content=kubeconfig_content,
            context="example-context",
        )

        assert isinstance(session, KubernetesSession)
        assert isinstance(session.api_client, client.ApiClient)
        assert isinstance(session.api_client.configuration, client.Configuration)
        assert session.api_client.configuration.verify_ssl is False
        assert session.api_client.configuration.proxy is None

    @patch(
        "prowler.providers.kubernetes.kubernetes_provider.client.CoreV1Api.list_namespace"
    )
    @patch("kubernetes.config.list_kube_config_contexts")
    @patch("kubernetes.config.load_kube_config_from_dict")
    def test_kubernetes_provider_kubeconfig_content(
        self,
        mock_load_kube_config_from_dict,
        mock_list_kube_config_contexts,
        mock_list_namespace,
    ):
        mock_load_kube_config_from_dict.return_value = None
        mock_list_kube_config_contexts.return_value = (
            [
                {
                    "name": "example-context",
                    "context": {
                        "cluster": "example-cluster",
                        "user": "example-user",
                    },
                }
            ],
            None,
        )
        mock_list_namespace.return_value.items = [
            client.V1Namespace(metadata=client.V1ObjectMeta(name="namespace-1")),
        ]

        kubeconfig_content = '{"apiVersion": "v1", "clusters": [{"cluster": {"server": "https://kubernetes.example.com"}, "name": "example-cluster"}], "contexts": [{"context": {"cluster": "example-cluster", "user": "example-user"}, "name": "example-context"}], "current-context": "example-context", "kind": "Config", "preferences": {}, "users": [{"name": "example-user", "user": {"token": "EXAMPLE_TOKEN"}}]}'

        session = KubernetesProvider.setup_session(
            kubeconfig_content=kubeconfig_content,
            context="example-context",
        )

        assert isinstance(session, KubernetesSession)
        assert isinstance(session.api_client, client.ApiClient)

        assert session.context == {
            "name": "example-context",
            "context": {
                "cluster": "example-cluster",
                "user": "example-user",
            },
        }

    @patch(
        "prowler.providers.kubernetes.kubernetes_provider.client.CoreV1Api.list_namespace"
    )
    @patch("kubernetes.config.list_kube_config_contexts")
    @patch("kubernetes.config.load_kube_config_from_dict")
    def test_kubernetes_provider_kubeconfig_content_proxy_settings(
        self,
        mock_load_kube_config_from_dict,
        mock_list_kube_config_contexts,
        mock_list_namespace,
        monkeypatch,
    ):
        monkeypatch.setenv("HTTPS_PROXY", "http://my.internal.proxy:8888")
        monkeypatch.setenv("K8S_SKIP_TLS_VERIFY", "true")

        mock_load_kube_config_from_dict.return_value = None
        mock_list_kube_config_contexts.return_value = (
            [
                {
                    "name": "example-context",
                    "context": {
                        "cluster": "example-cluster",
                        "user": "example-user",
                    },
                }
            ],
            None,
        )
        mock_list_namespace.return_value.items = [
            client.V1Namespace(metadata=client.V1ObjectMeta(name="namespace-1")),
        ]

        kubeconfig_content = '{"apiVersion": "v1", "clusters": [{"cluster": {"server": "https://kubernetes.example.com"}, "name": "example-cluster"}], "contexts": [{"context": {"cluster": "example-cluster", "user": "example-user"}, "name": "example-context"}], "current-context": "example-context", "kind": "Config", "preferences": {}, "users": [{"name": "example-user", "user": {"token": "EXAMPLE_TOKEN"}}]}'

        session = KubernetesProvider.setup_session(
            kubeconfig_content=kubeconfig_content,
            context="example-context",
        )

        assert isinstance(session, KubernetesSession)
        assert isinstance(session.api_client, client.ApiClient)

        assert session.context == {
            "name": "example-context",
            "context": {
                "cluster": "example-cluster",
                "user": "example-user",
            },
        }

        assert session.api_client.configuration.proxy == "http://my.internal.proxy:8888"
        assert session.api_client.configuration.verify_ssl is False

    def test_set_proxy_settings_no_proxy_no_tls_skip(self):
        """Test set_proxy_settings with no environment variables set."""
        with patch.dict("os.environ", {}, clear=True):
            config = KubernetesProvider.set_proxy_settings()

            # Verify it's a Configuration instance from kubernetes.client
            from kubernetes.client import Configuration

            assert isinstance(config, Configuration)

            assert hasattr(config, "proxy")
            assert config.proxy is None
            assert hasattr(config, "verify_ssl")
            assert config.verify_ssl is True

    def test_set_proxy_settings_with_https_proxy_uppercase(self):
        """Test set_proxy_settings with HTTPS_PROXY environment variable."""
        proxy_url = "http://proxy.example.com:8080"
        with patch.dict("os.environ", {"HTTPS_PROXY": proxy_url}, clear=True):
            config = KubernetesProvider.set_proxy_settings()

            # Verify it's a Configuration instance from kubernetes.client
            from kubernetes.client import Configuration

            assert isinstance(config, Configuration)

            assert config.proxy == proxy_url
            assert config.verify_ssl is True

    def test_set_proxy_settings_with_https_proxy_lowercase(self):
        """Test set_proxy_settings with https_proxy environment variable."""
        proxy_url = "http://proxy.example.com:3128"
        with patch.dict("os.environ", {"https_proxy": proxy_url}, clear=True):
            config = KubernetesProvider.set_proxy_settings()

            # Verify it's a Configuration instance from kubernetes.client
            from kubernetes.client import Configuration

            assert isinstance(config, Configuration)

            assert config.proxy == proxy_url
            assert config.verify_ssl is True

    def test_set_proxy_settings_uppercase_proxy_takes_precedence(self):
        """Test that HTTPS_PROXY takes precedence over https_proxy."""
        uppercase_proxy = "http://uppercase.proxy.com:8080"
        lowercase_proxy = "http://lowercase.proxy.com:3128"
        with patch.dict(
            "os.environ",
            {"HTTPS_PROXY": uppercase_proxy, "https_proxy": lowercase_proxy},
            clear=True,
        ):
            config = KubernetesProvider.set_proxy_settings()

            # Verify it's a Configuration instance from kubernetes.client
            from kubernetes.client import Configuration

            assert isinstance(config, Configuration)

            assert config.proxy == uppercase_proxy
            assert config.verify_ssl is True

    def test_set_proxy_settings_with_tls_skip_true(self):
        """Test set_proxy_settings with K8S_SKIP_TLS_VERIFY set to true."""
        with patch.dict("os.environ", {"K8S_SKIP_TLS_VERIFY": "true"}, clear=True):
            config = KubernetesProvider.set_proxy_settings()

            # Verify it's a Configuration instance from kubernetes.client
            from kubernetes.client import Configuration

            assert isinstance(config, Configuration)

            assert config.proxy is None
            assert config.verify_ssl is False

    def test_set_proxy_settings_with_tls_skip_true_uppercase(self):
        """Test set_proxy_settings with K8S_SKIP_TLS_VERIFY set to TRUE."""
        with patch.dict("os.environ", {"K8S_SKIP_TLS_VERIFY": "TRUE"}, clear=True):
            config = KubernetesProvider.set_proxy_settings()

            # Verify it's a Configuration instance from kubernetes.client
            from kubernetes.client import Configuration

            assert isinstance(config, Configuration)

            assert config.proxy is None
            assert config.verify_ssl is False

    def test_set_proxy_settings_with_tls_skip_false(self):
        """Test set_proxy_settings with K8S_SKIP_TLS_VERIFY set to false."""
        with patch.dict("os.environ", {"K8S_SKIP_TLS_VERIFY": "false"}, clear=True):
            config = KubernetesProvider.set_proxy_settings()

            # Verify it's a Configuration instance from kubernetes.client
            from kubernetes.client import Configuration

            assert isinstance(config, Configuration)

            assert config.proxy is None
            assert config.verify_ssl is True

    def test_set_proxy_settings_with_tls_skip_invalid_value(self):
        """Test set_proxy_settings with K8S_SKIP_TLS_VERIFY set to invalid value."""
        with patch.dict("os.environ", {"K8S_SKIP_TLS_VERIFY": "invalid"}, clear=True):
            config = KubernetesProvider.set_proxy_settings()

            # Verify it's a Configuration instance from kubernetes.client
            from kubernetes.client import Configuration

            assert isinstance(config, Configuration)

            assert config.proxy is None
            assert config.verify_ssl is True

    def test_set_proxy_settings_with_both_proxy_and_tls_skip(self):
        """Test set_proxy_settings with both proxy and TLS skip settings."""
        proxy_url = "http://secure.proxy.com:8080"
        with patch.dict(
            "os.environ",
            {"HTTPS_PROXY": proxy_url, "K8S_SKIP_TLS_VERIFY": "true"},
            clear=True,
        ):
            config = KubernetesProvider.set_proxy_settings()

            # Verify it's a Configuration instance from kubernetes.client
            from kubernetes.client import Configuration

            assert isinstance(config, Configuration)

            assert config.proxy == proxy_url
            assert config.verify_ssl is False
