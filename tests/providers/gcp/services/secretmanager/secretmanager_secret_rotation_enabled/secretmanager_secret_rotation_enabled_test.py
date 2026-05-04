from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider

_CLIENT_PATH = "prowler.providers.gcp.services.secretmanager.secretmanager_secret_rotation_enabled.secretmanager_secret_rotation_enabled.secretmanager_client"


def _client(secrets):
    c = mock.MagicMock()
    c.region = "global"
    c.secrets = secrets
    return c


class Test_secretmanager_secret_rotation_enabled:
    def test_no_secrets(self):
        with (
            mock.patch("prowler.providers.common.provider.Provider.get_global_provider", return_value=set_mocked_gcp_provider()),
            mock.patch(_CLIENT_PATH, new=_client([])),
        ):
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_rotation_enabled.secretmanager_secret_rotation_enabled import secretmanager_secret_rotation_enabled
            assert len(secretmanager_secret_rotation_enabled().execute()) == 0

    def test_rotation_90_days_pass(self):
        from prowler.providers.gcp.services.secretmanager.secretmanager_service import Secret
        s = Secret(id=f"projects/{GCP_PROJECT_ID}/secrets/s", name="s", project_id=GCP_PROJECT_ID, rotation_period="7776000s")
        with (mock.patch("prowler.providers.common.provider.Provider.get_global_provider", return_value=set_mocked_gcp_provider()), mock.patch(_CLIENT_PATH, new=_client([s]))):
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_rotation_enabled.secretmanager_secret_rotation_enabled import secretmanager_secret_rotation_enabled
            r = secretmanager_secret_rotation_enabled().execute()
            assert r[0].status == "PASS" and r[0].resource_id == "s"

    def test_rotation_110_days_fail(self):
        from prowler.providers.gcp.services.secretmanager.secretmanager_service import Secret
        s = Secret(id=f"projects/{GCP_PROJECT_ID}/secrets/s", name="s", project_id=GCP_PROJECT_ID, rotation_period="9504000s")
        with (mock.patch("prowler.providers.common.provider.Provider.get_global_provider", return_value=set_mocked_gcp_provider()), mock.patch(_CLIENT_PATH, new=_client([s]))):
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_rotation_enabled.secretmanager_secret_rotation_enabled import secretmanager_secret_rotation_enabled
            assert secretmanager_secret_rotation_enabled().execute()[0].status == "FAIL"

    def test_no_rotation_fail(self):
        from prowler.providers.gcp.services.secretmanager.secretmanager_service import Secret
        s = Secret(id=f"projects/{GCP_PROJECT_ID}/secrets/s", name="s", project_id=GCP_PROJECT_ID, rotation_period=None)
        with (mock.patch("prowler.providers.common.provider.Provider.get_global_provider", return_value=set_mocked_gcp_provider()), mock.patch(_CLIENT_PATH, new=_client([s]))):
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_rotation_enabled.secretmanager_secret_rotation_enabled import secretmanager_secret_rotation_enabled
            assert secretmanager_secret_rotation_enabled().execute()[0].status == "FAIL"

    def test_fractional_seconds_pass(self):
        from prowler.providers.gcp.services.secretmanager.secretmanager_service import Secret
        s = Secret(id=f"projects/{GCP_PROJECT_ID}/secrets/s", name="s", project_id=GCP_PROJECT_ID, rotation_period="2592000.500000000s")
        with (mock.patch("prowler.providers.common.provider.Provider.get_global_provider", return_value=set_mocked_gcp_provider()), mock.patch(_CLIENT_PATH, new=_client([s]))):
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_rotation_enabled.secretmanager_secret_rotation_enabled import secretmanager_secret_rotation_enabled
            assert secretmanager_secret_rotation_enabled().execute()[0].status == "PASS"

    def test_sub_day_rotation_pass(self):
        from prowler.providers.gcp.services.secretmanager.secretmanager_service import Secret
        s = Secret(id=f"projects/{GCP_PROJECT_ID}/secrets/s", name="s", project_id=GCP_PROJECT_ID, rotation_period="3600s")
        with (mock.patch("prowler.providers.common.provider.Provider.get_global_provider", return_value=set_mocked_gcp_provider()), mock.patch(_CLIENT_PATH, new=_client([s]))):
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_rotation_enabled.secretmanager_secret_rotation_enabled import secretmanager_secret_rotation_enabled
            assert secretmanager_secret_rotation_enabled().execute()[0].status == "PASS"

    def test_overdue_rotation_fail(self):
        from prowler.providers.gcp.services.secretmanager.secretmanager_service import Secret
        s = Secret(
            id=f"projects/{GCP_PROJECT_ID}/secrets/s",
            name="s",
            project_id=GCP_PROJECT_ID,
            rotation_period="7776000s",
            next_rotation_time="2020-01-01T00:00:00Z",
        )
        with (mock.patch("prowler.providers.common.provider.Provider.get_global_provider", return_value=set_mocked_gcp_provider()), mock.patch(_CLIENT_PATH, new=_client([s]))):
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_rotation_enabled.secretmanager_secret_rotation_enabled import secretmanager_secret_rotation_enabled
            result = secretmanager_secret_rotation_enabled().execute()
            assert result[0].status == "FAIL"
            assert "overdue" in result[0].status_extended