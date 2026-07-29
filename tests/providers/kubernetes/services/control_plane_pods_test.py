import importlib
from unittest import mock

from prowler.providers.kubernetes.services.core.core_service import Container, Pod
from tests.providers.kubernetes.kubernetes_fixtures import (
    set_mocked_kubernetes_provider,
)

# Each control-plane service scrapes kube-system pods whose name starts with a
# well-known prefix, then exposes them as `<service>_pods` for its checks.
CONTROL_PLANE_SERVICES = {
    "apiserver": {
        "module": "prowler.providers.kubernetes.services.apiserver.apiserver_service",
        "class": "APIServer",
        "attribute": "apiserver_pods",
        "pod_name": "kube-apiserver-control-plane",
        "check": (
            "prowler.providers.kubernetes.services.apiserver."
            "apiserver_anonymous_requests.apiserver_anonymous_requests"
        ),
        "check_class": "apiserver_anonymous_requests",
        "client_attr": "apiserver_client",
    },
    "controllermanager": {
        "module": (
            "prowler.providers.kubernetes.services.controllermanager."
            "controllermanager_service"
        ),
        "class": "ControllerManager",
        "attribute": "controllermanager_pods",
        "pod_name": "kube-controller-manager-control-plane",
        "check": (
            "prowler.providers.kubernetes.services.controllermanager."
            "controllermanager_disable_profiling.controllermanager_disable_profiling"
        ),
        "check_class": "controllermanager_disable_profiling",
        "client_attr": "controllermanager_client",
    },
    "etcd": {
        "module": "prowler.providers.kubernetes.services.etcd.etcd_service",
        "class": "Etcd",
        "attribute": "etcd_pods",
        "pod_name": "etcd-control-plane",
        "check": (
            "prowler.providers.kubernetes.services.etcd."
            "etcd_client_cert_auth.etcd_client_cert_auth"
        ),
        "check_class": "etcd_client_cert_auth",
        "client_attr": "etcd_client",
    },
    "scheduler": {
        "module": "prowler.providers.kubernetes.services.scheduler.scheduler_service",
        "class": "Scheduler",
        "attribute": "scheduler_pods",
        "pod_name": "kube-scheduler-control-plane",
        "check": (
            "prowler.providers.kubernetes.services.scheduler."
            "scheduler_bind_address.scheduler_bind_address"
        ),
        "check_class": "scheduler_bind_address",
        "client_attr": "scheduler_client",
    },
}


def make_pod(name, namespace="kube-system", command=None):
    return Pod(
        name=name,
        uid=f"{name}-uid",
        namespace=namespace,
        labels=None,
        annotations=None,
        node_name="control-plane",
        service_account=None,
        status_phase="Running",
        pod_ip="10.0.0.1",
        host_ip="192.168.1.1",
        host_pid=False,
        host_ipc=False,
        host_network=False,
        security_context={},
        containers={
            "container": Container(
                name="container",
                image="registry.k8s.io/kube-apiserver:v1.30.0",
                command=command if command is not None else [],
                ports=None,
                env=None,
                security_context={},
                resources=None,
                liveness_probe=None,
                readiness_probe=None,
            )
        },
        init_containers={},
        ephemeral_containers={},
        volumes=None,
    )


def build_service(spec, core_client):
    """Instantiate a control-plane service against a mocked core client."""
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_kubernetes_provider(),
        ),
        mock.patch(f"{spec['module']}.core_client", new=core_client),
    ):
        module = importlib.import_module(spec["module"])
        service_class = getattr(module, spec["class"])
        return service_class(set_mocked_kubernetes_provider())


def failing_core_client():
    """A core client whose pod collection raises, as it does on an API error."""
    core_client = mock.MagicMock()
    type(core_client).pods = mock.PropertyMock(
        side_effect=Exception("Kubernetes API unavailable")
    )
    return core_client


class Test_control_plane_pod_gathering:
    """Regression tests for control-plane pod gathering failures.

    ``_get_<service>_pods`` places its ``return`` inside the ``try`` block, so
    when the Kubernetes API call raises, the ``except`` branch only logs and the
    function falls through to an implicit ``return None``. That ``None`` is
    assigned straight to ``<service>_pods``, and every check that iterates it
    raises ``TypeError: 'NoneType' object is not iterable``.
    """

    def test_pods_are_gathered_and_filtered(self):
        """Sanity check: matching kube-system pods are collected."""
        for name, spec in CONTROL_PLANE_SERVICES.items():
            core_client = mock.MagicMock()
            core_client.pods = {
                "match": make_pod(spec["pod_name"]),
                # Right prefix, wrong namespace.
                "wrong-namespace": make_pod(spec["pod_name"], namespace="default"),
                # Right namespace, wrong prefix.
                "wrong-prefix": make_pod("unrelated-workload"),
            }

            service = build_service(spec, core_client)
            gathered = getattr(service, spec["attribute"])

            assert [pod.name for pod in gathered] == [
                spec["pod_name"]
            ], f"{name}: expected only the matching control-plane pod"

    def test_gather_failure_yields_empty_list_not_none(self):
        """A failed gather must not produce a non-iterable ``None``."""
        for name, spec in CONTROL_PLANE_SERVICES.items():
            service = build_service(spec, failing_core_client())
            gathered = getattr(service, spec["attribute"])

            assert gathered is not None, (
                f"{name}: {spec['attribute']} is None after a gather failure, "
                "which makes every check that iterates it raise TypeError"
            )
            assert gathered == [], f"{name}: expected an empty list"

    def test_checks_do_not_crash_when_gather_fails(self):
        """Checks must degrade to zero findings, not raise TypeError."""
        for name, spec in CONTROL_PLANE_SERVICES.items():
            service = build_service(spec, failing_core_client())

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=set_mocked_kubernetes_provider(),
                ),
                mock.patch(f"{spec['check']}.{spec['client_attr']}", new=service),
            ):
                check_module = importlib.import_module(spec["check"])
                check = getattr(check_module, spec["check_class"])()
                findings = check.execute()

            assert findings == [], f"{name}: expected no findings after a failed gather"
