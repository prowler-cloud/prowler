import pytest

from kubernetes import client
from prowler.providers.kubernetes.services.core.core_service import Core
from tests.providers.kubernetes.services.core.conftest import (
    make_container,
    make_core_client,
    make_pod,
    run_check,
)

MODULE = "prowler.providers.kubernetes.services.core.core_minimize_allowPrivilegeEscalation_containers.core_minimize_allowPrivilegeEscalation_containers"
CLASS = "core_minimize_allowPrivilegeEscalation_containers"


class TestCoreMinimizeAllowPrivilegeEscalationContainers:
    def test_no_pods(self):
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
    @pytest.mark.parametrize(
        "security_context",
        [
            pytest.param(None, id="no-security-context"),
            pytest.param(
                client.V1SecurityContext(read_only_root_filesystem=True), id="unset"
            ),
            pytest.param(
                client.V1SecurityContext(allow_privilege_escalation=True), id="true"
            ),
        ],
    )
    def test_requires_explicit_false(
        self, container_group, container_type, security_context
    ):
        pod = make_pod(
            containers={
                "app": make_container(
                    security_context={"allow_privilege_escalation": False}
                )
            }
        )
        container_name = "container-without-explicit-false"
        containers = Core._build_containers(
            [
                container_type(
                    name=container_name,
                    image="busybox:1.36",
                    security_context=security_context,
                )
            ]
        )
        getattr(pod, container_group).update(containers)

        findings = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert findings[0].status_extended == (
            f"Pod {pod.name} must set allowPrivilegeEscalation to false in container {container_name}."
        )

    def test_explicit_false_in_every_container_passes(self):
        security_context = {"allow_privilege_escalation": False}
        pod = make_pod(
            containers={"app": make_container(security_context=security_context)},
            init_containers={
                "init": make_container(name="init", security_context=security_context)
            },
            ephemeral_containers={
                "debug": make_container(name="debug", security_context=security_context)
            },
        )

        findings = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(findings) == 1
        assert findings[0].status == "PASS"

    def test_skips_windows_and_reports_other_pods(self):
        windows = make_pod(
            containers={"app": make_container()}, name="windows", uid="windows"
        )
        windows.os_name = "windows"
        linux = make_pod(
            containers={
                "app": make_container(
                    security_context={"allow_privilege_escalation": False}
                )
            },
            name="linux",
            uid="linux",
        )
        linux.os_name = "linux"
        linux.init_containers = None
        linux.ephemeral_containers = None
        unspecified_os = make_pod(
            containers={"app": make_container()}, name="os-unset", uid="os-unset"
        )
        pods = {pod.uid: pod for pod in (windows, linux, unspecified_os)}

        findings = run_check(MODULE, CLASS, make_core_client(pods))

        assert len(findings) == 2
        assert {finding.resource_id: finding.status for finding in findings} == {
            linux.uid: "PASS",
            unspecified_os.uid: "FAIL",
        }
