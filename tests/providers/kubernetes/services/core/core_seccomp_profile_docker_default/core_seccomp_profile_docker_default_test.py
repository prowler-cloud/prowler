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

CLASS = "core_seccomp_profile_docker_default"
MODULE = f"prowler.providers.kubernetes.services.core.{CLASS}.{CLASS}"
RUNTIME_DEFAULT_CONTEXT = {"seccomp_profile": {"type": "RuntimeDefault"}}


class TestCoreSeccompProfileDockerDefault:
    @pytest.fixture(autouse=True)
    def mock_core_api(self):
        with mock.patch.object(client, "CoreV1Api"):
            yield

    def test_no_resources(self):
        assert run_check(MODULE, CLASS, make_core_client({})) == []

    def test_missing_regular_containers_emits_no_finding(self):
        pod = make_pod()

        assert run_check(MODULE, CLASS, make_core_client({pod.uid: pod})) == []

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
    def test_unconfined_container_overrides_pod_runtime_default(
        self, container_group, container_type
    ):
        pod = make_pod(containers={"app": make_container()})
        pod.security_context = client.V1PodSecurityContext(
            seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault")
        ).to_dict()
        containers = Core._build_containers(
            [
                container_type(
                    name="unconfined-container",
                    image="busybox:1.36",
                    security_context=client.V1SecurityContext(
                        seccomp_profile=client.V1SeccompProfile(type="Unconfined")
                    ),
                )
            ]
        )
        getattr(pod, container_group).update(containers)

        findings = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "unconfined-container" in findings[0].status_extended
        assert "Unconfined" in findings[0].status_extended

    def test_containers_inherit_pod_runtime_default(self):
        pod = make_pod(
            containers={"app": make_container()},
            init_containers={
                "init": make_container(
                    name="init", security_context={"seccomp_profile": None}
                )
            },
            ephemeral_containers={"debug": make_container(name="debug")},
        )
        pod.security_context = RUNTIME_DEFAULT_CONTEXT

        findings = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(findings) == 1
        assert findings[0].status == "PASS"

    def test_all_containers_explicitly_configured_without_pod_profile(self):
        pod = make_pod(
            containers={
                "app": make_container(security_context=RUNTIME_DEFAULT_CONTEXT)
            },
            init_containers={
                "init": make_container(
                    name="init", security_context=RUNTIME_DEFAULT_CONTEXT
                )
            },
            ephemeral_containers={
                "debug": make_container(
                    name="debug", security_context=RUNTIME_DEFAULT_CONTEXT
                )
            },
        )

        findings = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(findings) == 1
        assert findings[0].status == "PASS"

    @pytest.mark.parametrize(
        "container_group", ["containers", "init_containers", "ephemeral_containers"]
    )
    def test_container_without_profile_or_pod_default_fails(self, container_group):
        pod = make_pod(
            containers={"app": make_container(security_context=RUNTIME_DEFAULT_CONTEXT)}
        )
        getattr(pod, container_group)["unconfigured"] = make_container(
            name="unconfigured"
        )

        findings = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "unconfigured" in findings[0].status_extended
        assert "unset" in findings[0].status_extended

    def test_localhost_override_does_not_satisfy_runtime_default(self):
        pod = make_pod(
            containers={
                "app": make_container(
                    security_context={
                        "seccomp_profile": {
                            "type": "Localhost",
                            "localhost_profile": "custom.json",
                        }
                    }
                )
            }
        )
        pod.security_context = RUNTIME_DEFAULT_CONTEXT

        findings = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "Localhost" in findings[0].status_extended

    def test_absent_optional_groups_pass(self):
        pod = make_pod(containers={"app": make_container()})
        pod.security_context = RUNTIME_DEFAULT_CONTEXT
        pod.init_containers = None
        pod.ephemeral_containers = None

        findings = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert len(findings) == 1
        assert findings[0].status == "PASS"
