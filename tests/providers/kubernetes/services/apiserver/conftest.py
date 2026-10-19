import importlib
from unittest import mock

from prowler.providers.kubernetes.services.core.core_service import Container, Pod
from tests.providers.kubernetes.kubernetes_fixtures import (
    set_mocked_kubernetes_provider,
)


def make_apiserver_container(command, name="kube-apiserver"):
    return Container(
        name=name,
        image="registry.k8s.io/kube-apiserver:v1.34.0",
        command=command,
        ports=None,
        env=None,
        security_context={},
        resources=None,
        liveness_probe=None,
        readiness_probe=None,
    )


def make_apiserver_pod(
    command,
    name="kube-apiserver-node-1",
    uid="kube-apiserver-node-1-uid",
):
    return Pod(
        name=name,
        uid=uid,
        namespace="kube-system",
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
        containers={
            "kube-apiserver": make_apiserver_container(command=command),
        },
    )


def run_check(module_path, class_name, pods):
    mock_client = mock.MagicMock()
    mock_client.apiserver_pods = pods
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_kubernetes_provider(),
        ),
        mock.patch(f"{module_path}.apiserver_client", new=mock_client),
    ):
        check_module = importlib.import_module(module_path)
        check = getattr(check_module, class_name)()
        return check.execute()
