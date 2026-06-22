from tests.providers.kubernetes.services.core.conftest import (
    make_container,
    make_core_client,
    make_pod,
    run_check,
)

MODULE = (
    "prowler.providers.kubernetes.services.core.core_cpu_limits_set.core_cpu_limits_set"
)
CLASS = "core_cpu_limits_set"


class TestCoreCpuLimitsSet:
    def test_no_resources(self):
        result = run_check(MODULE, CLASS, make_core_client({}))

        assert len(result) == 0

    def test_cpu_limit_set_pass(self):
        pod = make_pod(
            containers={"app": make_container(resources={"limits": {"cpu": "500m"}})}
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Pod test-pod regular containers have CPU limits configured."
        )

    def test_cpu_limit_missing_fail(self):
        pod = make_pod(containers={"app": make_container(resources=None)})

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Pod test-pod container app does not have a CPU limit configured."
        )

    def test_empty_cpu_limit_fail(self):
        pod = make_pod(
            containers={"app": make_container(resources={"limits": {"cpu": ""}})}
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "FAIL"

    def test_mixed_regular_containers_fail(self):
        pod = make_pod(
            containers={
                "app": make_container(
                    name="app", resources={"limits": {"cpu": "500m"}}
                ),
                "sidecar": make_container(name="sidecar", resources={"limits": {}}),
            }
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Pod test-pod container sidecar does not have a CPU limit configured."
        )

    def test_init_and_ephemeral_containers_ignored(self):
        pod = make_pod(
            containers={"app": make_container(resources={"limits": {"cpu": "500m"}})},
            init_containers={"init": make_container(name="init", resources=None)},
            ephemeral_containers={"debug": make_container(name="debug", resources=None)},
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "PASS"
