from tests.providers.kubernetes.services.apiserver.conftest import (
    make_apiserver_pod,
    run_check,
)

MODULE = (
    "prowler.providers.kubernetes.services.apiserver."
    "apiserver_auth_mode_not_always_allow.apiserver_auth_mode_not_always_allow"
)
CLASS = "apiserver_auth_mode_not_always_allow"

TALOS_COMMAND = [
    "kube-apiserver",
    "--authorization-config=/system/config/kubernetes/kube-apiserver/authorization-config.yaml",
    "--admission-control-config-file=/system/config/kubernetes/kube-apiserver/admission-control-config.yaml",
    "--etcd-servers=https://127.0.0.1:2379",
]


class TestApiserverAuthModeNotAlwaysAllow:
    def test_no_pods_no_findings(self):
        result = run_check(MODULE, CLASS, [])

        assert result == []

    def test_authorization_config_file_pass(self):
        pod = make_apiserver_pod(command=TALOS_COMMAND)

        result = run_check(MODULE, CLASS, [pod])

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "authorization-config" in result[0].status_extended

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

    def test_authorization_mode_rbac_pass(self):
        pod = make_apiserver_pod(
            command=["kube-apiserver", "--authorization-mode=RBAC,Node"]
        )

        result = run_check(MODULE, CLASS, [pod])

        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_authorization_mode_always_allow_fail(self):
        pod = make_apiserver_pod(
            command=["kube-apiserver", "--authorization-mode=AlwaysAllow"]
        )

        result = run_check(MODULE, CLASS, [pod])

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "AlwaysAllow" in result[0].status_extended

    def test_no_authorization_flags_fail(self):
        pod = make_apiserver_pod(
            command=["kube-apiserver", "--etcd-servers=https://127.0.0.1:2379"]
        )

        result = run_check(MODULE, CLASS, [pod])

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "AlwaysAllow" in result[0].status_extended
