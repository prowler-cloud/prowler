from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, GCP_US_CENTER1_LOCATION, set_mocked_gcp_provider

_CLIENT_PATH = "prowler.providers.gcp.services.cloudfunction.cloudfunction_function_not_publicly_accessible.cloudfunction_function_not_publicly_accessible.cloudfunction_client"


class Test_cloudfunction_function_not_publicly_accessible:
    def test_no_functions(self):
        c = mock.MagicMock(); c.functions = []
        with (mock.patch("prowler.providers.common.provider.Provider.get_global_provider", return_value=set_mocked_gcp_provider()), mock.patch(_CLIENT_PATH, new=c)):
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_function_not_publicly_accessible.cloudfunction_function_not_publicly_accessible import cloudfunction_function_not_publicly_accessible
            assert len(cloudfunction_function_not_publicly_accessible().execute()) == 0

    def test_function_private_pass(self):
        from prowler.providers.gcp.services.cloudfunction.cloudfunction_service import Function
        c = mock.MagicMock()
        c.functions = [Function(id=f"projects/{GCP_PROJECT_ID}/locations/{GCP_US_CENTER1_LOCATION}/functions/fn", name="fn", project_id=GCP_PROJECT_ID, location=GCP_US_CENTER1_LOCATION, state="ACTIVE", publicly_accessible=False)]
        with (mock.patch("prowler.providers.common.provider.Provider.get_global_provider", return_value=set_mocked_gcp_provider()), mock.patch(_CLIENT_PATH, new=c)):
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_function_not_publicly_accessible.cloudfunction_function_not_publicly_accessible import cloudfunction_function_not_publicly_accessible
            r = cloudfunction_function_not_publicly_accessible().execute()
            assert r[0].status == "PASS" and r[0].resource_id == "fn" and r[0].location == GCP_US_CENTER1_LOCATION and r[0].project_id == GCP_PROJECT_ID

    def test_function_public_fail(self):
        from prowler.providers.gcp.services.cloudfunction.cloudfunction_service import Function
        c = mock.MagicMock()
        c.functions = [Function(id=f"projects/{GCP_PROJECT_ID}/locations/{GCP_US_CENTER1_LOCATION}/functions/pub", name="pub", project_id=GCP_PROJECT_ID, location=GCP_US_CENTER1_LOCATION, state="ACTIVE", publicly_accessible=True)]
        with (mock.patch("prowler.providers.common.provider.Provider.get_global_provider", return_value=set_mocked_gcp_provider()), mock.patch(_CLIENT_PATH, new=c)):
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_function_not_publicly_accessible.cloudfunction_function_not_publicly_accessible import cloudfunction_function_not_publicly_accessible
            r = cloudfunction_function_not_publicly_accessible().execute()
            assert r[0].status == "FAIL" and r[0].resource_id == "pub"