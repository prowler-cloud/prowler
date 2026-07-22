from kubernetes import client
from prowler.providers.kubernetes.services.core.core_service import Core, Pod


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
