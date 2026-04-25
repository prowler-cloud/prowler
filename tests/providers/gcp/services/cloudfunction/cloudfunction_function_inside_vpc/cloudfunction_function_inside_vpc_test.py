from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, GCP_US_CENTER1_LOCATION, set_mocked_gcp_provider

_CLIENT_PATH = "prowler.providers.gcp.services.cloudfunction.cloudfunction_function_inside_vpc.cloudfunction_function_inside_vpc.cloudfunction_client"


class Test_cloudfunction_function_inside_vpc:
    def test_no_functions(self):
        c = mock.MagicMock(); c.functions = []
        with (mock.patch("prowler.providers.common.provider.Provider.get_global_provider", return_value=set_mocked_gcp_provider()), mock.patch(_CLIENT_PATH, new=c)):
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_function_inside_vpc.cloudfunction_function_inside_vpc import cloudfunction_function_inside_vpc
            assert len(cloudfunction_function_inside_vpc().execute()) == 0

    def test_function_with_vpc_pass(self):
        from prowler.providers.gcp.services.cloudfunction.cloudfunction_service import Function
        c = mock.MagicMock()
        c.functions = [Function(id=f"projects/{GCP_PROJECT_ID}/locations/{GCP_US_CENTER1_LOCATION}/functions/fn-vpc", name="fn-vpc", project_id=GCP_PROJECT_ID, location=GCP_US_CENTER1_LOCATION, state="ACTIVE", vpc_connector=f"projects/{GCP_PROJECT_ID}/locations/{GCP_US_CENTER1_LOCATION}/connectors/my-connector")]
        with (mock.patch("prowler.providers.common.provider.Provider.get_global_provider", return_value=set_mocked_gcp_provider()), mock.patch(_CLIENT_PATH, new=c)):
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_function_inside_vpc.cloudfunction_function_inside_vpc import cloudfunction_function_inside_vpc
            r = cloudfunction_function_inside_vpc().execute()
            assert r[0].status == "PASS" and r[0].resource_id == "fn-vpc" and r[0].location == GCP_US_CENTER1_LOCATION and r[0].project_id == GCP_PROJECT_ID

    def test_function_without_vpc_fail(self):
        from prowler.providers.gcp.services.cloudfunction.cloudfunction_service import Function
        c = mock.MagicMock()
        c.functions = [Function(id=f"projects/{GCP_PROJECT_ID}/locations/{GCP_US_CENTER1_LOCATION}/functions/fn-public", name="fn-public", project_id=GCP_PROJECT_ID, location=GCP_US_CENTER1_LOCATION, state="ACTIVE", vpc_connector=None)]
        with (mock.patch("prowler.providers.common.provider.Provider.get_global_provider", return_value=set_mocked_gcp_provider()), mock.patch(_CLIENT_PATH, new=c)):
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_function_inside_vpc.cloudfunction_function_inside_vpc import cloudfunction_function_inside_vpc
            r = cloudfunction_function_inside_vpc().execute()
            assert r[0].status == "FAIL" and r[0].resource_id == "fn-public"