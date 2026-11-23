from unittest import mock

import pytest

from kubernetes import client
from prowler.providers.kubernetes.services.core.core_service import Core, Pod
from tests.providers.kubernetes.kubernetes_fixtures import (
    set_mocked_kubernetes_provider,
)


@pytest.mark.parametrize("os_name", ["linux", "windows", None])
def test_get_pods_preserves_declared_os(os_name):
    provider = set_mocked_kubernetes_provider()
    provider.namespaces = ["default"]
    pod = client.V1Pod(
        metadata=client.V1ObjectMeta(
            name="test-pod", uid="test-pod-uid", namespace="default"
        ),
        spec=client.V1PodSpec(
            containers=[client.V1Container(name="app", image="test-image:1")],
            os=client.V1PodOS(name=os_name) if os_name else None,
        ),
        status=client.V1PodStatus(phase="Running"),
    )

    with mock.patch.object(client, "CoreV1Api") as core_api:
        core_api.return_value.list_namespaced_pod.return_value = client.V1PodList(
            items=[pod]
        )
        core = Core(provider)

    assert core.pods[pod.metadata.uid].os_name == os_name


def test_pod_model_preserves_core_service_container_groups():
    containers = Core._build_containers(
        [
            client.V1Container(
                name="app",
                image="nginx:1.25",
                security_context=client.V1SecurityContext(
                    read_only_root_filesystem=True
                ),
            )
        ]
    )
    init_containers = Core._build_containers(
        [
            client.V1Container(
                name="init",
                image="busybox:1.36",
                security_context=client.V1SecurityContext(
                    read_only_root_filesystem=True
                ),
            )
        ]
    )
    ephemeral_containers = Core._build_containers(
        [
            client.V1EphemeralContainer(
                name="debug",
                image="busybox:1.36",
                security_context=client.V1SecurityContext(
                    read_only_root_filesystem=True
                ),
            )
        ]
    )

    pod = Pod(
        name="test-pod",
        uid="test-pod-uid",
        namespace="default",
        labels=None,
        annotations=None,
        node_name=None,
        service_account=None,
        status_phase="Running",
        pod_ip="10.0.0.1",
        host_ip="192.168.1.1",
        host_pid=False,
        host_ipc=False,
        host_network=False,
        security_context={},
        containers=containers,
        init_containers=init_containers,
        ephemeral_containers=ephemeral_containers,
    )

    assert list(pod.containers) == ["app"]
    assert list(pod.init_containers) == ["init"]
    assert list(pod.ephemeral_containers) == ["debug"]
    assert "init" not in pod.containers
    assert "debug" not in pod.containers


@pytest.mark.parametrize("host_port", [8080, 0, None])
def test_build_containers_preserves_hostport(host_port):
    """Preserve nonzero, zero, and omitted HostPorts during container collection."""
    containers = Core._build_containers(
        [
            client.V1Container(
                name="app",
                image="nginx:1.25",
                ports=[client.V1ContainerPort(container_port=80, host_port=host_port)],
            )
        ]
    )

    assert containers["app"].ports == [{"containerPort": 80, "hostPort": host_port}]
