from unittest import mock

import pytest

from kubernetes import client
from prowler.providers.kubernetes.services.core.core_service import Core
from tests.providers.kubernetes.services.core.conftest import (
    make_container,
    make_core_client,
    make_pod,
    run_check,
)

CHECK_NAME = "core_minimize_admission_hostport_containers"
MODULE_PATH = f"prowler.providers.kubernetes.services.core.{CHECK_NAME}.{CHECK_NAME}"


def collect_pod(containers):
    """Collect a mocked SDK Pod through the real service and data models."""
    core = Core.__new__(Core)
    core.namespaces = ["default"]
    core.pods = {}
    core.client = mock.MagicMock()
    core.client.list_namespaced_pod.return_value = client.V1PodList(
        items=[
            client.V1Pod(
                metadata=client.V1ObjectMeta(
                    name="test-pod", uid="test-pod-uid", namespace="default"
                ),
                spec=client.V1PodSpec(containers=containers),
                status=client.V1PodStatus(phase="Running"),
            )
        ]
    )
    core._get_pods()
    assert list(core.pods) == ["test-pod-uid"]
    return core


def test_hostport_collected_from_api_fails_check():
    core = collect_pod(
        [
            client.V1Container(
                name="app",
                image="nginx:1.25",
                ports=[client.V1ContainerPort(container_port=80, host_port=8080)],
            )
        ]
    )

    findings = run_check(MODULE_PATH, CHECK_NAME, core)

    assert len(findings) == 1
    assert findings[0].status == "FAIL"
    assert findings[0].status_extended == (
        "Pod test-pod uses HostPorts in container app."
    )
    assert findings[0].resource_id == "test-pod-uid"
    assert findings[0].resource_name == "test-pod"
    assert findings[0].namespace == "default"


@pytest.mark.parametrize(
    "port_groups, expected_status, failing_container",
    [
        pytest.param([[(80, 0)]], "PASS", None, id="zero-hostport"),
        pytest.param([[(8080, None)]], "PASS", None, id="omitted-hostport"),
        pytest.param([None], "PASS", None, id="no-ports"),
        pytest.param([[]], "PASS", None, id="empty-ports"),
        pytest.param(
            [[(80, None)], [(80, 8080)]], "FAIL", "app-1", id="second-container"
        ),
        pytest.param([[(80, 8080)], [(80, 0)]], "FAIL", "app-0", id="first-container"),
        pytest.param(
            [[(80, None)], [(8080, 0)], None], "PASS", None, id="all-containers-safe"
        ),
        pytest.param([[(80, 0), (443, 8443)]], "FAIL", "app-0", id="second-port"),
        pytest.param([[(80, 1)]], "FAIL", "app-0", id="minimum-hostport"),
        pytest.param([[(80, 65535)]], "FAIL", "app-0", id="maximum-hostport"),
    ],
)
def test_hostport_collection_and_check(port_groups, expected_status, failing_container):
    containers = [
        client.V1Container(
            name=f"app-{index}",
            image="nginx:1.25",
            ports=(
                [
                    client.V1ContainerPort(
                        container_port=container_port, host_port=host_port
                    )
                    for container_port, host_port in ports
                ]
                if ports is not None
                else None
            ),
        )
        for index, ports in enumerate(port_groups)
    ]
    core = collect_pod(containers)

    findings = run_check(MODULE_PATH, CHECK_NAME, core)

    assert len(findings) == 1
    assert findings[0].status == expected_status
    assert findings[0].status_extended == (
        f"Pod test-pod uses HostPorts in container {failing_container}."
        if failing_container is not None
        else "Pod test-pod does not use HostPorts."
    )
    assert findings[0].resource_id == "test-pod-uid"
    assert findings[0].resource_name == "test-pod"
    assert findings[0].namespace == "default"


@pytest.mark.parametrize(
    "ports, expected_status",
    [
        ([{"containerPort": 80, "hostPort": 8080}], "FAIL"),
        ([{"containerPort": 80, "hostPort": 0}], "PASS"),
        ([{"containerPort": 80, "hostPort": None}], "PASS"),
        ([{"containerPort": 8080}], "PASS"),
    ],
)
def test_hostport_check_on_collected_model(ports, expected_status):
    container = make_container()
    container.ports = ports
    pod = make_pod(containers={"app": container})
    core = make_core_client({pod.uid: pod})

    findings = run_check(MODULE_PATH, CHECK_NAME, core)

    assert len(findings) == 1
    assert findings[0].status == expected_status


def test_no_pods():
    assert run_check(MODULE_PATH, CHECK_NAME, make_core_client({})) == []
