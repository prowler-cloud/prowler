from unittest import mock

from prowler.providers.kubernetes.services.core.core_service import Container, Pod
from tests.providers.kubernetes.kubernetes_fixtures import (
    set_mocked_kubernetes_provider,
)


class Test_core_image_tag_fixed:
    def test_no_pods(self):
        core_client = mock.MagicMock
        core_client.pods = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_kubernetes_provider(),
            ),
            mock.patch(
                "prowler.providers.kubernetes.services.core.core_image_tag_fixed.core_image_tag_fixed.core_client",
                new=core_client,
            ),
        ):
            from prowler.providers.kubernetes.services.core.core_image_tag_fixed.core_image_tag_fixed import (
                core_image_tag_fixed,
            )

            check = core_image_tag_fixed()
            result = check.execute()

            assert len(result) == 0

    def test_image_tag_fixed(self):
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
                "prowler.providers.kubernetes.services.core.core_image_tag_fixed.core_image_tag_fixed.core_client",
                new=core_client,
            ),
        ):
            from prowler.providers.kubernetes.services.core.core_image_tag_fixed.core_image_tag_fixed import (
                core_image_tag_fixed,
            )

            check = core_image_tag_fixed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "Pod test-pod has fixed image tags on all containers."
            )
            assert result[0].resource_id == "test-uid-1234"
            assert result[0].resource_name == "test-pod"

    def test_image_tag_latest(self):
        container = Container(
            name="test-container",
            image="nginx:latest",
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
                "prowler.providers.kubernetes.services.core.core_image_tag_fixed.core_image_tag_fixed.core_client",
                new=core_client,
            ),
        ):
            from prowler.providers.kubernetes.services.core.core_image_tag_fixed.core_image_tag_fixed import (
                core_image_tag_fixed,
            )

            check = core_image_tag_fixed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "does not use a fixed tag" in result[0].status_extended
            )

    def test_image_tag_blank(self):
        container = Container(
            name="test-container",
            image="nginx",
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
                "prowler.providers.kubernetes.services.core.core_image_tag_fixed.core_image_tag_fixed.core_client",
                new=core_client,
            ),
        ):
            from prowler.providers.kubernetes.services.core.core_image_tag_fixed.core_image_tag_fixed import (
                core_image_tag_fixed,
            )

            check = core_image_tag_fixed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "does not use a fixed tag" in result[0].status_extended
            )

    def test_image_with_digest(self):
        container = Container(
            name="test-container",
            image="nginx@sha256:abc123def456",
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
                "prowler.providers.kubernetes.services.core.core_image_tag_fixed.core_image_tag_fixed.core_client",
                new=core_client,
            ),
        ):
            from prowler.providers.kubernetes.services.core.core_image_tag_fixed.core_image_tag_fixed import (
                core_image_tag_fixed,
            )

            check = core_image_tag_fixed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_image_with_registry_port_and_no_tag(self):
        container = Container(
            name="test-container",
            image="localhost:5000/nginx",
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
                "prowler.providers.kubernetes.services.core.core_image_tag_fixed.core_image_tag_fixed.core_client",
                new=core_client,
            ),
        ):
            from prowler.providers.kubernetes.services.core.core_image_tag_fixed.core_image_tag_fixed import (
                core_image_tag_fixed,
            )

            check = core_image_tag_fixed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not use a fixed tag" in result[0].status_extended

    def test_image_tag_uppercase_latest(self):
        container = Container(
            name="test-container",
            image="nginx:Latest",
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
                "prowler.providers.kubernetes.services.core.core_image_tag_fixed.core_image_tag_fixed.core_client",
                new=core_client,
            ),
        ):
            from prowler.providers.kubernetes.services.core.core_image_tag_fixed.core_image_tag_fixed import (
                core_image_tag_fixed,
            )

            check = core_image_tag_fixed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not use a fixed tag" in result[0].status_extended

    def test_image_with_empty_tag(self):
        container = Container(
            name="test-container",
            image="nginx:",
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
                "prowler.providers.kubernetes.services.core.core_image_tag_fixed.core_image_tag_fixed.core_client",
                new=core_client,
            ),
        ):
            from prowler.providers.kubernetes.services.core.core_image_tag_fixed.core_image_tag_fixed import (
                core_image_tag_fixed,
            )

            check = core_image_tag_fixed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not use a fixed tag" in result[0].status_extended

    def test_mixed_containers_fails_on_first_unfixed_image(self):
        fixed_container = Container(
            name="fixed-container",
            image="nginx:1.25.3",
            command=None,
            ports=None,
            env=None,
            security_context={},
            resources=None,
        )
        latest_container = Container(
            name="latest-container",
            image="busybox:latest",
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
            containers={
                "fixed-container": fixed_container,
                "latest-container": latest_container,
            },
        )

        core_client = mock.MagicMock
        core_client.pods = {"test-uid-1234": pod}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_kubernetes_provider(),
            ),
            mock.patch(
                "prowler.providers.kubernetes.services.core.core_image_tag_fixed.core_image_tag_fixed.core_client",
                new=core_client,
            ),
        ):
            from prowler.providers.kubernetes.services.core.core_image_tag_fixed.core_image_tag_fixed import (
                core_image_tag_fixed,
            )

            check = core_image_tag_fixed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "Pod test-pod has container latest-container with image 'busybox:latest' that does not use a fixed tag."
            )
