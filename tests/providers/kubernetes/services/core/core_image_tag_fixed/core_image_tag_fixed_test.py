from tests.providers.kubernetes.services.core.conftest import (
    make_container,
    make_core_client,
    make_pod,
    run_check,
)

MODULE = "prowler.providers.kubernetes.services.core.core_image_tag_fixed.core_image_tag_fixed"
CLASS = "core_image_tag_fixed"


class TestCoreImageTagFixed:
    def test_no_resources(self):
        result = run_check(MODULE, CLASS, make_core_client({}))

        assert len(result) == 0

    def test_fixed_image_tag_pass(self):
        pod = make_pod(containers={"app": make_container(image="nginx:1.25")})

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Pod test-pod regular containers use fixed image tags."
        )

    def test_missing_image_tag_fail(self):
        pod = make_pod(containers={"app": make_container(image="nginx")})

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Pod test-pod container app uses an unfixed image tag: nginx."
        )

    def test_empty_image_fail(self):
        pod = make_pod(containers={"app": make_container(image="")})

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Pod test-pod container app uses an unfixed image tag: ."
        )

    def test_mixed_regular_containers_fail(self):
        pod = make_pod(
            containers={
                "app": make_container(name="app", image="nginx:1.25"),
                "sidecar": make_container(name="sidecar", image="redis"),
            }
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Pod test-pod container sidecar uses an unfixed image tag: redis."
        )

    def test_init_and_ephemeral_containers_ignored(self):
        pod = make_pod(
            containers={"app": make_container(image="nginx:1.25")},
            init_containers={"init": make_container(name="init", image="busybox")},
            ephemeral_containers={
                "debug": make_container(name="debug", image="alpine")
            },
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "PASS"

    def test_registry_port_with_fixed_tag_pass(self):
        pod = make_pod(
            containers={"app": make_container(image="localhost:5000/app:v1")}
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "PASS"

    def test_registry_port_without_tag_fail(self):
        pod = make_pod(containers={"app": make_container(image="registry:5000/app")})

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "FAIL"

    def test_image_digest_pass(self):
        pod = make_pod(
            containers={
                "app": make_container(
                    image="nginx@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                )
            }
        )

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "PASS"

    def test_latest_tag_case_insensitive_fail(self):
        pod = make_pod(containers={"app": make_container(image="nginx:LaTeSt")})

        result = run_check(MODULE, CLASS, make_core_client({pod.uid: pod}))

        assert result[0].status == "FAIL"
