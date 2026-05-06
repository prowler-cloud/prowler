from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider

_CLIENT_PATH = "prowler.providers.gcp.services.secretmanager.secretmanager_secret_not_publicly_accessible.secretmanager_secret_not_publicly_accessible.secretmanager_client"


class Test_secretmanager_secret_not_publicly_accessible:
    def test_no_secrets(self):
        c = mock.MagicMock(); c.region = "global"; c.secrets = []
        with (mock.patch("prowler.providers.common.provider.Provider.get_global_provider", return_value=set_mocked_gcp_provider()), mock.patch(_CLIENT_PATH, new=c)):
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_not_publicly_accessible.secretmanager_secret_not_publicly_accessible import secretmanager_secret_not_publicly_accessible
            assert len(secretmanager_secret_not_publicly_accessible().execute()) == 0

    def test_secret_private_pass(self):
        from prowler.providers.gcp.services.secretmanager.secretmanager_service import Secret
        c = mock.MagicMock(); c.region = "global"
        c.secrets = [Secret(id=f"projects/{GCP_PROJECT_ID}/secrets/priv", name="priv", project_id=GCP_PROJECT_ID, publicly_accessible=False)]
        with (mock.patch("prowler.providers.common.provider.Provider.get_global_provider", return_value=set_mocked_gcp_provider()), mock.patch(_CLIENT_PATH, new=c)):
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_not_publicly_accessible.secretmanager_secret_not_publicly_accessible import secretmanager_secret_not_publicly_accessible
            r = secretmanager_secret_not_publicly_accessible().execute()
            assert r[0].status == "PASS" and r[0].resource_id == "priv" and r[0].project_id == GCP_PROJECT_ID

    def test_secret_public_fail(self):
        from prowler.providers.gcp.services.secretmanager.secretmanager_service import Secret
        c = mock.MagicMock(); c.region = "global"
        c.secrets = [Secret(id=f"projects/{GCP_PROJECT_ID}/secrets/pub", name="pub", project_id=GCP_PROJECT_ID, publicly_accessible=True)]
        with (mock.patch("prowler.providers.common.provider.Provider.get_global_provider", return_value=set_mocked_gcp_provider()), mock.patch(_CLIENT_PATH, new=c)):
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_not_publicly_accessible.secretmanager_secret_not_publicly_accessible import secretmanager_secret_not_publicly_accessible
            r = secretmanager_secret_not_publicly_accessible().execute()
            assert r[0].status == "FAIL" and r[0].resource_id == "pub"