from tests.providers.kubernetes.services.apiserver.conftest import (
    make_apiserver_pod,
    make_apiserver_pod_with_containers,
    run_check,
)

MODULE = (
    "prowler.providers.kubernetes.services.apiserver."
    "apiserver_auth_mode_include_rbac.apiserver_auth_mode_include_rbac"
)
CLASS = "apiserver_auth_mode_include_rbac"

TALOS_COMMAND = [
    "kube-apiserver",
    "--authorization-config=/system/config/kubernetes/kube-apiserver/authorization-config.yaml",
    "--admission-control-config-file=/system/config/kubernetes/kube-apiserver/admission-control-config.yaml",
    "--etcd-servers=https://127.0.0.1:2379",
]


class TestApiserverAuthModeIncludeRbac:
    def test_no_pods_no_findings(self):
        result = run_check(MODULE, CLASS, [])

        assert result == []

    def test_authorization_config_file_pass(self):
        pod = make_apiserver_pod(command=TALOS_COMMAND)

        result = run_check(MODULE, CLASS, [pod])

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "authorization-config" in result[0].status_extended
        assert "was not inspected" in result[0].status_extended

    def test_authorization_config_separate_arg_pass(self):
        pod = make_apiserver_pod(
            command=[
                "kube-apiserver",
                "--authorization-config",
                "/system/config/kubernetes/kube-apiserver/authorization-config.yaml",
            ]
        )

        result = run_check(MODULE, CLASS, [pod])

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "authorization-config" in result[0].status_extended

    def test_authorization_config_in_later_container_pass(self):
        pod = make_apiserver_pod_with_containers(
            [
                ["kube-apiserver", "--etcd-servers=https://127.0.0.1:2379"],
                TALOS_COMMAND,
            ]
        )

        result = run_check(MODULE, CLASS, [pod])

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "authorization-config" in result[0].status_extended

    def test_authorization_mode_includes_rbac_pass(self):
        pod = make_apiserver_pod(
            command=["kube-apiserver", "--authorization-mode=Node,RBAC"]
        )

        result = run_check(MODULE, CLASS, [pod])

        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_authorization_mode_space_separated_pass(self):
        pod = make_apiserver_pod(
            command=["kube-apiserver", "--authorization-mode", "Node,RBAC"]
        )

        result = run_check(MODULE, CLASS, [pod])

        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_authorization_mode_without_rbac_fail(self):
        pod = make_apiserver_pod(
            command=["kube-apiserver", "--authorization-mode=AlwaysAllow"]
        )

        result = run_check(MODULE, CLASS, [pod])

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "RBAC" in result[0].status_extended

    def test_no_authorization_flags_fail(self):
        pod = make_apiserver_pod(
            command=["kube-apiserver", "--etcd-servers=https://127.0.0.1:2379"]
        )

        result = run_check(MODULE, CLASS, [pod])

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "RBAC" in result[0].status_extended

    def test_container_without_command_no_crash(self):
        pod = make_apiserver_pod(command=None)

        result = run_check(MODULE, CLASS, [pod])

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "RBAC" in result[0].status_extended

    def test_authorization_config_with_always_allow_mode_pass(self):
        # --authorization-config makes --authorization-mode inert, so an
        # AlwaysAllow value there must not flip the verdict.
        pod = make_apiserver_pod(
            command=TALOS_COMMAND + ["--authorization-mode=AlwaysAllow"]
        )

        result = run_check(MODULE, CLASS, [pod])

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "authorization-config" in result[0].status_extended

    def test_bare_authorization_config_token_pass(self):
        pod = make_apiserver_pod(command=["kube-apiserver", "--authorization-config"])

        result = run_check(MODULE, CLASS, [pod])

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "authorization-config" in result[0].status_extended
