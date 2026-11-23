import importlib
from unittest import mock

from prowler.providers.kubernetes.services.core.core_service import (
    ConfigMap,
    Container,
    Pod,
)
from tests.providers.kubernetes.kubernetes_fixtures import (
    set_mocked_kubernetes_provider,
)

# Each of these services scrapes a subset of the resources already collected by
# the core service, then exposes the result for its checks to iterate.
#
#   source     - attribute read off the mocked core client
#   attribute  - attribute the service exposes to its checks
#   match/miss - a resource that should and should not be collected
GATHERERS = {
    "apiserver": {
        "module": "prowler.providers.kubernetes.services.apiserver.apiserver_service",
        "class": "APIServer",
        "source": "pods",
        "namespaced": True,
        "attribute": "apiserver_pods",
        "match": "kube-apiserver-control-plane",
        "miss": "unrelated-workload",
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
        "source": "pods",
        "namespaced": True,
        "attribute": "controllermanager_pods",
        "match": "kube-controller-manager-control-plane",
        "miss": "unrelated-workload",
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
        "source": "pods",
        "namespaced": True,
        "attribute": "etcd_pods",
        "match": "etcd-control-plane",
        "miss": "unrelated-workload",
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
        "source": "pods",
        "namespaced": True,
        "attribute": "scheduler_pods",
        "match": "kube-scheduler-control-plane",
        "miss": "unrelated-workload",
        "check": (
            "prowler.providers.kubernetes.services.scheduler."
            "scheduler_bind_address.scheduler_bind_address"
        ),
        "check_class": "scheduler_bind_address",
        "client_attr": "scheduler_client",
    },
    "kubelet": {
        "module": "prowler.providers.kubernetes.services.kubelet.kubelet_service",
        "class": "Kubelet",
        "source": "config_maps",
        "namespaced": False,
        "attribute": "kubelet_config_maps",
        "match": "kubelet-config-node",
        "miss": "unrelated-config",
        "check": (
            "prowler.providers.kubernetes.services.kubelet."
            "kubelet_disable_anonymous_auth.kubelet_disable_anonymous_auth"
        ),
        "check_class": "kubelet_disable_anonymous_auth",
        "client_attr": "kubelet_client",
    },
}


def make_pod(name, namespace="kube-system"):
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
                command=[],
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


def make_config_map(name, namespace="kube-system"):
    return ConfigMap(
        name=name,
        uid=f"{name}-uid",
        namespace=namespace,
        data={"kubelet": "authentication:\n  anonymous:\n    enabled: false\n"},
    )


def make_resource(spec, name, namespace="kube-system"):
    if spec["source"] == "pods":
        return make_pod(name, namespace)
    return make_config_map(name, namespace)


def build_service(spec, core_client):
    """Instantiate a service against a mocked core client."""
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


def failing_core_client(spec):
    """A core client whose resource collection raises, as on an API error."""
    core_client = mock.MagicMock()
    setattr(
        type(core_client),
        spec["source"],
        mock.PropertyMock(side_effect=Exception("Kubernetes API unavailable")),
    )
    return core_client


class Test_kubernetes_resource_gathering:
    """Regression tests for failed resource gathering in Kubernetes services.

    Before this fix, ``_get_<service>_pods`` and ``_get_kubelet_config_maps``
    placed their ``return`` inside the ``try`` block, so when resource
    collection raised, the ``except`` branch only logged and the function fell
    through to an implicit ``return None``. That ``None`` was assigned straight
    to the service attribute, and every check that iterates it raised
    ``TypeError: 'NoneType' object is not iterable``.
    """

    def test_resources_are_gathered_and_filtered(self):
        """Sanity check: only matching resources are collected.

        The pod gatherers filter on both namespace and name prefix; the kubelet
        gatherer matches on name prefix alone, so a same-named config map in
        another namespace is expected to be collected there.
        """
        for name, spec in GATHERERS.items():
            core_client = mock.MagicMock()
            setattr(
                core_client,
                spec["source"],
                {
                    "match": make_resource(spec, spec["match"]),
                    # Right prefix, different namespace.
                    "other-namespace": make_resource(
                        spec, spec["match"], namespace="default"
                    ),
                    # Right namespace, wrong prefix.
                    "wrong-prefix": make_resource(spec, spec["miss"]),
                },
            )

            service = build_service(spec, core_client)
            gathered = getattr(service, spec["attribute"])

            expected = [(spec["match"], "kube-system")]
            if not spec["namespaced"]:
                expected.append((spec["match"], "default"))
            assert [(item.name, item.namespace) for item in gathered] == expected, (
                f"{name}: expected only the matching resource(s); "
                f"namespaced={spec['namespaced']}"
            )

    def test_gather_failure_yields_empty_list_not_none(self):
        """A failed gather must not produce a non-iterable ``None``."""
        for name, spec in GATHERERS.items():
            service = build_service(spec, failing_core_client(spec))
            gathered = getattr(service, spec["attribute"])

            assert gathered is not None, (
                f"{name}: {spec['attribute']} is None after a gather failure, "
                "which makes every check that iterates it raise TypeError"
            )
            assert gathered == [], f"{name}: expected an empty list"

    def test_checks_do_not_crash_when_gather_fails(self):
        """Checks must degrade to zero findings, not raise TypeError."""
        for name, spec in GATHERERS.items():
            service = build_service(spec, failing_core_client(spec))

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


class Test_kubelet_config_map_parsing:
    """A broken `kubelet-config*` ConfigMap must not hide the valid ones."""

    def _kubelet_config_maps(self, config_maps):
        spec = GATHERERS["kubelet"]
        core_client = mock.MagicMock()
        core_client.config_maps = config_maps
        return build_service(spec, core_client).kubelet_config_maps

    def test_malformed_yaml_config_map_is_skipped(self):
        bad = ConfigMap(
            name="kubelet-config-bad",
            uid="bad-uid",
            namespace="kube-system",
            data={"kubelet": "authentication: [unclosed"},
        )
        good = make_config_map("kubelet-config")

        # The broken ConfigMap is listed first, so an early return would lose
        # the valid one that follows it.
        gathered = self._kubelet_config_maps({"bad": bad, "good": good})

        assert [cm.name for cm in gathered] == ["kubelet-config"]
        assert gathered[0].kubelet_args["authentication"]["anonymous"] == {
            "enabled": False
        }

    def test_config_map_without_data_is_kept_with_empty_args(self):
        empty = ConfigMap(
            name="kubelet-config-empty", uid="empty-uid", namespace="kube-system"
        )
        good = make_config_map("kubelet-config")

        gathered = self._kubelet_config_maps({"empty": empty, "good": good})

        assert [cm.name for cm in gathered] == [
            "kubelet-config-empty",
            "kubelet-config",
        ]
        # Checks use both `key not in cm.kubelet_args` and `cm.kubelet_args.get`,
        # so an empty configuration must be a dict, not a list.
        assert gathered[0].kubelet_args == {}
