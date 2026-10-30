from unittest.mock import Mock, patch

from kubernetes.client.rest import ApiException

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


def _make_pod(name, namespace, uid):
    """Build a minimal V1Pod for Core service tests."""
    return client.V1Pod(
        metadata=client.V1ObjectMeta(name=name, namespace=namespace, uid=uid),
        spec=client.V1PodSpec(
            containers=[client.V1Container(name="app", image="nginx:1.25")]
        ),
        status=client.V1PodStatus(
            phase="Running", pod_ip="10.0.0.1", host_ip="192.168.1.1"
        ),
    )


def _build_core(namespaces, list_side_effect):
    """Instantiate Core without running __init__, with a mocked API client."""
    core = Core.__new__(Core)
    core.namespaces = namespaces
    core.pods = {}
    core.client = Mock()
    core.client.list_namespaced_pod.side_effect = list_side_effect
    return core


def _pod_list_for(namespace):
    """Return a one-pod V1PodList for the given namespace."""
    return client.V1PodList(
        items=[_make_pod(f"pod-{namespace}", namespace, f"uid-{namespace}")]
    )


def test_get_pods_lists_every_namespace():
    """Pods from every namespace are listed and stored."""
    core = _build_core(["default", "kube-system"], lambda ns: _pod_list_for(ns))

    core._get_pods()

    assert [
        call.args[0] for call in core.client.list_namespaced_pod.call_args_list
    ] == ["default", "kube-system"]
    assert set(core.pods) == {"uid-default", "uid-kube-system"}


def test_get_pods_continues_after_namespace_error():
    """A failing namespace does not skip the others, and pods from
    successful namespaces are actually stored."""

    def list_namespaced_pod(namespace):
        if namespace == "forbidden":
            raise ApiException(status=403, reason="Forbidden")
        return _pod_list_for(namespace)

    core = _build_core(["default", "forbidden", "kube-system"], list_namespaced_pod)

    core._get_pods()

    assert [
        call.args[0] for call in core.client.list_namespaced_pod.call_args_list
    ] == ["default", "forbidden", "kube-system"]
    assert set(core.pods) == {"uid-default", "uid-kube-system"}


def test_get_pods_first_namespace_error_does_not_skip_the_rest():
    """A failure in the first namespace does not skip the remaining ones."""

    def list_namespaced_pod(namespace):
        if namespace == "forbidden":
            raise ApiException(status=403, reason="Forbidden")
        return _pod_list_for(namespace)

    core = _build_core(["forbidden", "default"], list_namespaced_pod)

    core._get_pods()

    assert set(core.pods) == {"uid-default"}


def test_get_pods_conversion_error_does_not_skip_the_rest():
    """A pod conversion failure in the first namespace does not skip the
    remaining ones."""
    core = _build_core(["default", "kube-system"], lambda ns: _pod_list_for(ns))

    with patch.object(
        Core, "_build_volumes", side_effect=[RuntimeError("invalid volume"), []]
    ):
        core._get_pods()

    assert set(core.pods) == {"uid-kube-system"}


def test_get_pods_logs_namespace_on_error():
    """The error log identifies the failing namespace and exception class."""

    def list_namespaced_pod(namespace):
        raise ApiException(status=403, reason="Forbidden")

    core = _build_core(["forbidden"], list_namespaced_pod)

    with patch(
        "prowler.providers.kubernetes.services.core.core_service.logger"
    ) as mock_logger:
        core._get_pods()

    mock_logger.error.assert_called_once()
    message = mock_logger.error.call_args.args[0]
    assert "forbidden" in message
    assert "ApiException" in message


def test_get_pods_all_namespaces_fail():
    """Every namespace failing yields no pods and no propagated exception.
    This documents current behavior: a fully failed scan is stored the
    same way as an empty one."""

    def list_namespaced_pod(namespace):
        raise ApiException(status=403, reason="Forbidden")

    core = _build_core(["default", "kube-system"], list_namespaced_pod)

    with patch(
        "prowler.providers.kubernetes.services.core.core_service.logger"
    ) as mock_logger:
        core._get_pods()

    assert core.pods == {}
    assert mock_logger.error.call_count == 2
    messages = [call.args[0] for call in mock_logger.error.call_args_list]
    assert "default" in messages[0]
    assert "kube-system" in messages[1]


def test_get_pods_records_failed_namespaces():
    """Namespaces whose pod listing fails are recorded on the service."""

    def list_namespaced_pod(namespace):
        if namespace == "forbidden":
            raise ApiException(status=403, reason="Forbidden")
        return _pod_list_for(namespace)

    core = _build_core(["default", "forbidden", "kube-system"], list_namespaced_pod)

    core._get_pods()

    assert core.failed_namespaces == ["forbidden"]
    assert set(core.pods) == {"uid-default", "uid-kube-system"}


def test_get_pods_warns_when_namespaces_fail():
    """A partial failure logs one warning naming the failed namespaces."""

    def list_namespaced_pod(namespace):
        if namespace == "forbidden":
            raise ApiException(status=403, reason="Forbidden")
        return _pod_list_for(namespace)

    core = _build_core(["default", "forbidden", "kube-system"], list_namespaced_pod)

    with patch(
        "prowler.providers.kubernetes.services.core.core_service.logger"
    ) as mock_logger:
        core._get_pods()

    mock_logger.warning.assert_called_once()
    message = mock_logger.warning.call_args.args[0]
    assert "forbidden" in message
    assert "1 of 3" in message


def test_get_pods_all_fail_records_every_namespace():
    """When every namespace fails, all of them are recorded and the
    warning reports the full count."""

    def list_namespaced_pod(namespace):
        raise ApiException(status=403, reason="Forbidden")

    core = _build_core(["default", "kube-system"], list_namespaced_pod)

    with patch(
        "prowler.providers.kubernetes.services.core.core_service.logger"
    ) as mock_logger:
        core._get_pods()

    assert core.pods == {}
    assert core.failed_namespaces == ["default", "kube-system"]
    mock_logger.warning.assert_called_once()
    assert "2 of 2" in mock_logger.warning.call_args.args[0]


def test_get_pods_no_failures_no_warning():
    """A clean listing records no failures and logs no warning."""
    core = _build_core(["default", "kube-system"], lambda ns: _pod_list_for(ns))

    with patch(
        "prowler.providers.kubernetes.services.core.core_service.logger"
    ) as mock_logger:
        core._get_pods()

    assert core.failed_namespaces == []
    mock_logger.warning.assert_not_called()
