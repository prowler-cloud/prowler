from tests.providers.kubernetes.services.core.conftest import (
    make_container,
    make_core_client,
    make_pod,
    run_check,
)

MODULE = "prowler.providers.kubernetes.services.core.core_readiness_probe_configured.core_readiness_probe_configured"
CLASS = "core_readiness_probe_configured"


class TestCoreReadinessProbeConfigured:
    def test_no_resources(self):
        result = run_check(MODULE, CLASS, make_core_client({}))

        assert len(result) == 0

    def test_readiness_probe_configured_pass(self):
        pod = make_pod(containers={"app": make_container(readiness_probe={"http_get": {}})})

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Pod test-pod has readiness probes configured for all regular containers."
        )

    def test_readiness_probe_missing_fail(self):
        pod = make_pod(containers={"app": make_container(readiness_probe=None)})

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Pod test-pod container app does not have a readiness probe configured."
        )

    def test_empty_readiness_probe_fail(self):
        pod = make_pod(containers={"app": make_container(readiness_probe={})})

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Pod test-pod container app does not have a readiness probe configured."
        )

    def test_mixed_regular_containers_fail(self):
        pod = make_pod(
            containers={
                "app": make_container(name="app", readiness_probe={"http_get": {}}),
                "sidecar": make_container(name="sidecar", readiness_probe=None),
            }
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Pod test-pod container sidecar does not have a readiness probe configured."
        )

    def test_init_and_ephemeral_containers_ignored(self):
        pod = make_pod(
            containers={"app": make_container(readiness_probe={"http_get": {}})},
            init_containers={"init": make_container(name="init", readiness_probe=None)},
            ephemeral_containers={"debug": make_container(name="debug", readiness_probe=None)},
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "PASS"
