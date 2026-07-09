from tests.providers.kubernetes.services.core.conftest import (
    make_core_client,
    make_pod,
    run_check,
)

MODULE = "prowler.providers.kubernetes.services.core.core_minimize_hostpath_volume_mounts.core_minimize_hostpath_volume_mounts"
CLASS = "core_minimize_hostpath_volume_mounts"


class TestCoreMinimizeHostpathVolumeMounts:
    def test_no_pods(self):
        result = run_check(MODULE, CLASS, make_core_client({}))

        assert len(result) == 0

    def test_pod_without_volumes_pass(self):
        pod = make_pod(volumes=[])

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended == "Pod test-pod does not mount hostPath volumes."
        )

    def test_pod_with_non_hostpath_volumes_pass(self):
        pod = make_pod(
            volumes=[
                {"name": "config", "config_map": {"name": "app-config"}},
                {"name": "scratch", "empty_dir": {}},
            ]
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended == "Pod test-pod does not mount hostPath volumes."
        )

    def test_pod_with_hostpath_volume_fail(self):
        pod = make_pod(
            volumes=[
                {"name": "host-logs", "host_path": {"path": "/var/log"}},
            ]
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Pod test-pod mounts hostPath volumes: host-logs."
        )

    def test_pod_with_mixed_volumes_fail(self):
        pod = make_pod(
            volumes=[
                {"name": "scratch", "empty_dir": {}},
                {
                    "name": "docker-socket",
                    "host_path": {"path": "/var/run/docker.sock"},
                },
                {"name": "host-etc", "host_path": {"path": "/etc"}},
            ]
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Pod test-pod mounts hostPath volumes: docker-socket, host-etc."
        )

    def test_pod_with_none_hostpath_key_pass(self):
        # V1Volume.to_dict() emits host_path: None for non-hostPath volumes
        pod = make_pod(
            volumes=[
                {"name": "scratch", "empty_dir": {}, "host_path": None},
            ]
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(result) == 1
        assert result[0].status == "PASS"
