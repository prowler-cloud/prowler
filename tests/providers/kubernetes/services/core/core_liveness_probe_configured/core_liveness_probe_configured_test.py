from tests.providers.kubernetes.services.core.conftest import (
    make_container,
    make_core_client,
    make_pod,
    run_check,
)

MODULE = "prowler.providers.kubernetes.services.core.core_liveness_probe_configured.core_liveness_probe_configured"
CLASS = "core_liveness_probe_configured"


class TestCoreLivenessProbeConfigured:
    def test_no_resources(self):
        result = run_check(MODULE, CLASS, make_core_client({}))

        assert len(result) == 0

    def test_liveness_probe_configured_pass(self):
        pod = make_pod(
            containers={"app": make_container(liveness_probe={"http_get": {}})}
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Pod test-pod has liveness probes configured for all regular containers."
        )

    def test_liveness_probe_missing_fail(self):
        pod = make_pod(containers={"app": make_container(liveness_probe=None)})

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Pod test-pod container app does not have a liveness probe configured."
        )

    def test_empty_liveness_probe_fail(self):
        pod = make_pod(containers={"app": make_container(liveness_probe={})})

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Pod test-pod container app does not have a liveness probe configured."
        )

    def test_mixed_regular_containers_fail(self):
        pod = make_pod(
            containers={
                "app": make_container(name="app", liveness_probe={"http_get": {}}),
                "sidecar": make_container(name="sidecar", liveness_probe=None),
            }
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Pod test-pod container sidecar does not have a liveness probe configured."
        )

    def test_init_and_ephemeral_containers_ignored(self):
        pod = make_pod(
            containers={"app": make_container(liveness_probe={"http_get": {}})},
            init_containers={"init": make_container(name="init", liveness_probe=None)},
            ephemeral_containers={
                "debug": make_container(name="debug", liveness_probe=None)
            },
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "PASS"
