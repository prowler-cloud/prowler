import pytest

from kubernetes import client
from prowler.providers.kubernetes.services.core.core_service import Core
from tests.providers.kubernetes.services.core.conftest import (
    make_container,
    make_core_client,
    make_pod,
    run_check,
)

MODULE = "prowler.providers.kubernetes.services.core.core_minimize_privileged_containers.core_minimize_privileged_containers"
CLASS = "core_minimize_privileged_containers"


class TestCoreMinimizePrivilegedContainers:
    def test_no_resources(self):
        assert run_check(MODULE, CLASS, make_core_client({})) == []

    @pytest.mark.parametrize(
        ("container_group", "container_type"),
        [
            pytest.param("containers", client.V1Container, id="regular"),
            pytest.param("init_containers", client.V1Container, id="init"),
            pytest.param(
                "ephemeral_containers", client.V1EphemeralContainer, id="ephemeral"
            ),
        ],
    )
    def test_privileged_container_fails(self, container_group, container_type):
        pod = make_pod(
            containers={"app": make_container(security_context={"privileged": False})}
        )
        container_name = "privileged-container"
        containers = Core._build_containers(
            [
                container_type(
                    name=container_name,
                    image="busybox:1.36",
                    security_context=client.V1SecurityContext(privileged=True),
                )
            ]
        )
        getattr(pod, container_group).update(containers)

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            f"Pod {pod.name} contains a privileged container {container_name}."
        )

    def test_non_privileged_and_unset_containers_pass(self):
        pod = make_pod(
            containers={"app": make_container(security_context={"privileged": False})},
            init_containers={
                "init": make_container(
                    name="init", security_context={"privileged": None}
                )
            },
            ephemeral_containers={"debug": make_container(name="debug")},
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_absent_optional_container_groups_pass(self):
        pod = make_pod(containers={"app": make_container()})
        pod.init_containers = None
        pod.ephemeral_containers = None

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(result) == 1
        assert result[0].status == "PASS"
