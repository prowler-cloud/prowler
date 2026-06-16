from tests.providers.kubernetes.services.core.conftest import (
    make_container,
    make_core_client,
    make_pod,
    run_check,
)

MODULE = "prowler.providers.kubernetes.services.core.core_memory_requests_set.core_memory_requests_set"
CLASS = "core_memory_requests_set"


class TestCoreMemoryRequestsSet:
    def test_no_resources(self):
        result = run_check(MODULE, CLASS, make_core_client({}))

        assert len(result) == 0

    def test_memory_request_set_pass(self):
        pod = make_pod(
            containers={
                "app": make_container(resources={"requests": {"memory": "128Mi"}})
            }
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Pod test-pod regular containers have memory requests configured."
        )

    def test_memory_request_missing_fail(self):
        pod = make_pod(containers={"app": make_container(resources={"requests": {}})})

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Pod test-pod container app does not have a memory request configured."
        )

    def test_empty_memory_request_fail(self):
        pod = make_pod(
            containers={"app": make_container(resources={"requests": {"memory": ""}})}
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "FAIL"

    def test_mixed_regular_containers_fail(self):
        pod = make_pod(
            containers={
                "app": make_container(
                    name="app", resources={"requests": {"memory": "128Mi"}}
                ),
                "sidecar": make_container(name="sidecar", resources=None),
            }
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Pod test-pod container sidecar does not have a memory request configured."
        )

    def test_init_and_ephemeral_containers_ignored(self):
        pod = make_pod(
            containers={
                "app": make_container(resources={"requests": {"memory": "128Mi"}})
            },
            init_containers={"init": make_container(name="init", resources=None)},
            ephemeral_containers={
                "debug": make_container(name="debug", resources=None)
            },
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "PASS"
