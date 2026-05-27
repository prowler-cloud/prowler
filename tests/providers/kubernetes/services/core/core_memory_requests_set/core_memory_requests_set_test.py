from unittest import mock

from prowler.providers.kubernetes.services.core.core_service import Container, Pod
from tests.providers.kubernetes.kubernetes_fixtures import (
    set_mocked_kubernetes_provider,
)


class Test_core_memory_requests_set:
    def test_no_pods(self):
        core_client = mock.MagicMock
        core_client.pods = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_kubernetes_provider(),
            ),
            mock.patch(
                "prowler.providers.kubernetes.services.core.core_memory_requests_set.core_client",
                new=core_client,
            ),
        ):
            from prowler.providers.kubernetes.services.core.core_memory_requests_set import (
                core_memory_requests_set,
            )

            check = core_memory_requests_set()
            result = check.execute()

            assert len(result) == 0

    def test_memory_requests_set(self):
        container = Container(
            name="test-container",
            image="nginx:1.25.3",
            command=None,
            ports=None,
            env=None,
            security_context={},
            resources={
                "limits": {"memory": "128Mi", "cpu": "500m"},
                "requests": {"memory": "64Mi", "cpu": "250m"},
            },
        )

        pod = Pod(
            name="test-pod",
            uid="test-uid-1234",
            namespace="default",
            labels=None,
            annotations=None,
            node_name=None,
            service_account=None,
            status_phase="Running",
            pod_ip="10.0.0.1",
            host_ip="192.168.1.1",
            host_pid=None,
            host_ipc=None,
            host_network=False,
            security_context={},
            containers={"test-container": container},
        )

        core_client = mock.MagicMock
        core_client.pods = {"test-uid-1234": pod}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_kubernetes_provider(),
            ),
            mock.patch(
                "prowler.providers.kubernetes.services.core.core_memory_requests_set.core_client",
                new=core_client,
            ),
        ):
            from prowler.providers.kubernetes.services.core.core_memory_requests_set import (
                core_memory_requests_set,
            )

            check = core_memory_requests_set()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "Pod test-pod has memory requests set on all containers."
            )
            assert result[0].resource_id == "test-uid-1234"
            assert result[0].resource_name == "test-pod"

    def test_memory_requests_not_set(self):
        container = Container(
            name="test-container",
            image="nginx:1.25.3",
            command=None,
            ports=None,
            env=None,
            security_context={},
            resources=None,
        )

        pod = Pod(
            name="test-pod",
            uid="test-uid-1234",
            namespace="default",
            labels=None,
            annotations=None,
            node_name=None,
            service_account=None,
            status_phase="Running",
            pod_ip="10.0.0.1",
            host_ip="192.168.1.1",
            host_pid=None,
            host_ipc=None,
            host_network=False,
            security_context={},
            containers={"test-container": container},
        )

        core_client = mock.MagicMock
        core_client.pods = {"test-uid-1234": pod}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_kubernetes_provider(),
            ),
            mock.patch(
                "prowler.providers.kubernetes.services.core.core_memory_requests_set.core_client",
                new=core_client,
            ),
        ):
            from prowler.providers.kubernetes.services.core.core_memory_requests_set import (
                core_memory_requests_set,
            )

            check = core_memory_requests_set()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "Pod test-pod does not have memory requests set on container test-container."
            )

    def test_memory_requests_missing_memory_key(self):
        container = Container(
            name="test-container",
            image="nginx:1.25.3",
            command=None,
            ports=None,
            env=None,
            security_context={},
            resources={
                "limits": {"memory": "128Mi"},
                "requests": {"cpu": "250m"},
            },
        )

        pod = Pod(
            name="test-pod",
            uid="test-uid-1234",
            namespace="default",
            labels=None,
            annotations=None,
            node_name=None,
            service_account=None,
            status_phase="Running",
            pod_ip="10.0.0.1",
            host_ip="192.168.1.1",
            host_pid=None,
            host_ipc=None,
            host_network=False,
            security_context={},
            containers={"test-container": container},
        )

        core_client = mock.MagicMock
        core_client.pods = {"test-uid-1234": pod}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_kubernetes_provider(),
            ),
            mock.patch(
                "prowler.providers.kubernetes.services.core.core_memory_requests_set.core_client",
                new=core_client,
            ),
        ):
            from prowler.providers.kubernetes.services.core.core_memory_requests_set import (
                core_memory_requests_set,
            )

            check = core_memory_requests_set()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
