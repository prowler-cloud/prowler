from tests.providers.kubernetes.services.core.conftest import (
    make_container,
    make_core_client,
    make_pod,
    run_check,
)

MODULE = "prowler.providers.kubernetes.services.core.core_readonly_root_filesystem_enabled.core_readonly_root_filesystem_enabled"
CLASS = "core_readonly_root_filesystem_enabled"


class TestCoreReadonlyRootFilesystemEnabled:
    def test_no_resources(self):
        result = run_check(MODULE, CLASS, make_core_client({}))

        assert len(result) == 0

    def test_readonly_root_filesystem_enabled_pass(self):
        pod = make_pod(
            containers={
                "app": make_container(
                    security_context={"read_only_root_filesystem": True}
                )
            }
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Pod test-pod has read-only root filesystem enabled for all containers."
        )

    def test_readonly_root_filesystem_false_fail(self):
        pod = make_pod(
            containers={
                "app": make_container(
                    security_context={"read_only_root_filesystem": False}
                )
            }
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Pod test-pod container app does not have readOnlyRootFilesystem set to true."
        )

    def test_readonly_root_filesystem_unset_fail(self):
        pod = make_pod(containers={"app": make_container(security_context={})})

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Pod test-pod container app does not have readOnlyRootFilesystem set to true."
        )

    def test_mixed_containers_fail(self):
        pod = make_pod(
            containers={
                "app": make_container(
                    name="app",
                    security_context={"read_only_root_filesystem": True},
                ),
                "sidecar": make_container(
                    name="sidecar",
                    security_context={"read_only_root_filesystem": False},
                ),
            }
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Pod test-pod container sidecar does not have readOnlyRootFilesystem set to true."
        )

    def test_init_containers_ignored(self):
        pod = make_pod(
            containers={
                "app": make_container(
                    security_context={"read_only_root_filesystem": True}
                )
            },
            init_containers={
                "init": make_container(name="init", security_context=None)
            },
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "PASS"
