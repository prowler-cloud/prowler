import importlib
from unittest import mock

from prowler.providers.kubernetes.services.core.core_service import Container, Pod
from tests.providers.kubernetes.kubernetes_fixtures import (
    set_mocked_kubernetes_provider,
)


def make_container(
    name="app",
    image="nginx:1.25",
    resources=None,
    liveness_probe=None,
    readiness_probe=None,
    security_context=None,
):
    return Container(
        name=name,
        image=image,
        command=None,
        ports=None,
        env=None,
        security_context=security_context if security_context is not None else {},
        resources=resources,
        liveness_probe=liveness_probe,
        readiness_probe=readiness_probe,
    )


def make_pod(
    containers=None,
    init_containers=None,
    ephemeral_containers=None,
    name="test-pod",
    uid="test-pod-uid",
):
    return Pod(
        name=name,
        uid=uid,
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
        containers=containers or {},
        init_containers=init_containers or {},
        ephemeral_containers=ephemeral_containers or {},
    )


def make_core_client(pods):
    core_client = mock.MagicMock()
    core_client.pods = pods
    return core_client


def run_check(module_path, class_name, core_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_kubernetes_provider(),
        ),
        mock.patch(f"{module_path}.core_client", new=core_client),
    ):
        check_module = importlib.import_module(module_path)
        check = getattr(check_module, class_name)()
        return check.execute()
