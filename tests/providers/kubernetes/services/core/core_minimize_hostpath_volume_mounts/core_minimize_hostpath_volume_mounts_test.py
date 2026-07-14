from kubernetes import client
from prowler.providers.kubernetes.services.core.core_service import Core
from tests.providers.kubernetes.services.core.conftest import (
    make_core_client,
    make_pod,
    run_check,
)

MODULE = (
    "prowler.providers.kubernetes.services.core."
    "core_minimize_hostpath_volume_mounts.core_minimize_hostpath_volume_mounts"
)
CLASS = "core_minimize_hostpath_volume_mounts"


class TestCoreMinimizeHostpathVolumeMounts:
    def test_build_volumes_maps_kubernetes_hostpath_volume(self):
        volumes = Core._build_volumes(
            [
                client.V1Volume(
                    name="host-logs",
                    host_path=client.V1HostPathVolumeSource(
                        path="/var/log",
                        type="Directory",
                    ),
                )
            ]
        )

        assert volumes == [
            {
                "name": "host-logs",
                "host_path": {"path": "/var/log", "type": "Directory"},
            }
        ]

    def test_no_resources(self):
        result = run_check(MODULE, CLASS, make_core_client({}))

        assert len(result) == 0

    def test_no_hostpath_volumes_pass(self):
        pod = make_pod(
            volumes=[
                {"name": "config", "host_path": None},
                {"name": "scratch", "host_path": None},
            ]
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "PASS"
        assert (
            result[0].status_extended == "Pod test-pod does not use hostPath volumes."
        )

    def test_hostpath_volume_fails(self):
        pod = make_pod(
            volumes=[
                {
                    "name": "host-logs",
                    "host_path": {"path": "/var/log", "type": "Directory"},
                }
            ]
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended == "Pod test-pod uses hostPath volume host-logs."
        )

    def test_mixed_volumes_fail_on_hostpath(self):
        pod = make_pod(
            volumes=[
                {"name": "config", "host_path": None},
                {
                    "name": "host-socket",
                    "host_path": {"path": "/var/run/docker.sock", "type": "Socket"},
                },
            ]
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Pod test-pod uses hostPath volume host-socket."
        )
