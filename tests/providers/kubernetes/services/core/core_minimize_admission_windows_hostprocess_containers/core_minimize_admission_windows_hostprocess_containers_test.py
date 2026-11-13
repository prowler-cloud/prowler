import pytest

from tests.providers.kubernetes.services.core.conftest import (
    make_container,
    make_core_client,
    make_pod,
    run_check,
)

CHECK_ID = "core_minimize_admission_windows_hostprocess_containers"
MODULE = f"prowler.providers.kubernetes.services.core.{CHECK_ID}.{CHECK_ID}"


def test_hostprocess_enabled_at_pod_level_fails():
    pod = make_pod(containers={"app": make_container()})
    pod.security_context = {"windows_options": {"host_process": True}}

    findings = run_check(MODULE, CHECK_ID, make_core_client({pod.uid: pod}))

    assert len(findings) == 1
    assert findings[0].status == "FAIL"


@pytest.mark.parametrize(
    "container_group",
    ["containers", "init_containers", "ephemeral_containers"],
)
def test_hostprocess_enabled_in_container_fails(container_group):
    container = make_container(
        security_context={"windows_options": {"host_process": True}}
    )
    pod = make_pod(**{container_group: {"app": container}})

    findings = run_check(MODULE, CHECK_ID, make_core_client({pod.uid: pod}))

    assert len(findings) == 1
    assert findings[0].status == "FAIL"


@pytest.mark.parametrize(
    "security_context",
    [
        {},
        {"windows_options": None},
        {"windows_options": {}},
        {"windows_options": {"host_process": False}},
    ],
)
def test_hostprocess_disabled_or_unset_passes(security_context):
    pod = make_pod(
        containers={"app": make_container(security_context=security_context)}
    )

    findings = run_check(MODULE, CHECK_ID, make_core_client({pod.uid: pod}))

    assert len(findings) == 1
    assert findings[0].status == "PASS"