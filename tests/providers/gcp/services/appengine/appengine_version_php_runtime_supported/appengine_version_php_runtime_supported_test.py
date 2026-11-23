from unittest import mock

import pytest

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)

CHECK_PATH = "prowler.providers.gcp.services.appengine.appengine_version_php_runtime_supported.appengine_version_php_runtime_supported"


def _version(runtime, env="standard", serving_status="SERVING"):
    from prowler.providers.gcp.services.appengine.appengine_service import Version

    return Version(
        id=f"apps/{GCP_PROJECT_ID}/services/default/versions/v1",
        name="default/v1",
        version_id="v1",
        service="default",
        project_id=GCP_PROJECT_ID,
        location=GCP_US_CENTER1_LOCATION,
        runtime=runtime,
        env=env,
        serving_status=serving_status,
    )


def _run_check(versions, audit_config=None):
    appengine_client = mock.MagicMock()
    appengine_client.versions = versions
    appengine_client.audit_config = audit_config or {}

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.appengine_client", new=appengine_client),
    ):
        from prowler.providers.gcp.services.appengine.appengine_version_php_runtime_supported.appengine_version_php_runtime_supported import (
            appengine_version_php_runtime_supported,
        )

        return appengine_version_php_runtime_supported().execute()


class Test_appengine_version_php_runtime_supported:
    def test_no_versions(self):
        assert len(_run_check([])) == 0

    @pytest.mark.parametrize(
        "runtime,env,serving_status",
        [
            ("python312", "standard", "SERVING"),
            ("nodejs20", "standard", "SERVING"),
            ("php82", "standard", "STOPPED"),
            ("custom", "flexible", "SERVING"),
        ],
    )
    def test_skipped_versions(self, runtime, env, serving_status):
        assert len(_run_check([_version(runtime, env, serving_status)])) == 0

    @pytest.mark.parametrize(
        "runtime,expected_status,expected_message",
        [
            (
                "php82",
                "PASS",
                "App Engine version default/v1 runs PHP 8.2 ('php82'), a supported runtime that receives security fixes automatically.",
            ),
            (
                "php85",
                "PASS",
                "App Engine version default/v1 runs PHP 8.5 ('php85'), a supported runtime that receives security fixes automatically.",
            ),
            (
                "php81",
                "FAIL",
                "App Engine version default/v1 runs PHP 8.1 ('php81'), a runtime that no longer receives security fixes (minimum supported version is 8.2).",
            ),
            (
                "php55",
                "FAIL",
                "App Engine version default/v1 runs PHP 5.5 ('php55'), a runtime that no longer receives security fixes (minimum supported version is 8.2).",
            ),
        ],
    )
    def test_standard_runtime(self, runtime, expected_status, expected_message):
        result = _run_check([_version(runtime)])
        assert len(result) == 1
        assert result[0].status == expected_status
        assert result[0].status_extended == expected_message
        assert (
            result[0].resource_id
            == f"apps/{GCP_PROJECT_ID}/services/default/versions/v1"
        )
        assert result[0].resource_name == "default/v1"
        assert result[0].project_id == GCP_PROJECT_ID
        assert result[0].location == GCP_US_CENTER1_LOCATION

    def test_flexible_runtime_is_manual(self):
        result = _run_check([_version("php", env="flexible")])
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == "App Engine version default/v1 runs on the flexible environment with runtime 'php', which is not patched in place; redeploy it on a fixed PHP release (8.2 or newer) and verify the image."
        )

    def test_custom_minimum(self):
        result = _run_check([_version("php83")], {"appengine_php_min_version": "8.4"})
        assert len(result) == 1
        assert result[0].status == "FAIL"
