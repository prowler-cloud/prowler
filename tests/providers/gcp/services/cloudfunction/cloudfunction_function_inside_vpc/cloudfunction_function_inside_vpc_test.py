from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)

_CHECK_PATH = (
    "prowler.providers.gcp.services.cloudfunction."
    "cloudfunction_function_inside_vpc.cloudfunction_function_inside_vpc"
)
_CLIENT_PATH = f"{_CHECK_PATH}.cloudfunction_client"


class Test_cloudfunction_function_inside_vpc:
    def test_no_functions(self):
        cloudfunction_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                _CLIENT_PATH,
                new=cloudfunction_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_function_inside_vpc.cloudfunction_function_inside_vpc import (
                cloudfunction_function_inside_vpc,
            )

            cloudfunction_client.functions = []

            check = cloudfunction_function_inside_vpc()
            result = check.execute()
            assert len(result) == 0

    def test_function_with_vpc_connector(self):
        cloudfunction_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                _CLIENT_PATH,
                new=cloudfunction_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_function_inside_vpc.cloudfunction_function_inside_vpc import (
                cloudfunction_function_inside_vpc,
            )
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_service import (
                Function,
            )

            connector = (
                f"projects/{GCP_PROJECT_ID}/locations/{GCP_US_CENTER1_LOCATION}"
                f"/connectors/my-connector"
            )
            cloudfunction_client.functions = [
                Function(
                    name="fn-vpc",
                    project_id=GCP_PROJECT_ID,
                    location=GCP_US_CENTER1_LOCATION,
                    state="ACTIVE",
                    vpc_connector=connector,
                )
            ]

            check = cloudfunction_function_inside_vpc()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Cloud Function fn-vpc is connected to a VPC via connector: {connector}."
            )
            assert result[0].resource_id == "fn-vpc"
            assert result[0].resource_name == "fn-vpc"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_function_without_vpc_connector(self):
        cloudfunction_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                _CLIENT_PATH,
                new=cloudfunction_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_function_inside_vpc.cloudfunction_function_inside_vpc import (
                cloudfunction_function_inside_vpc,
            )
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_service import (
                Function,
            )

            cloudfunction_client.functions = [
                Function(
                    name="fn-public",
                    project_id=GCP_PROJECT_ID,
                    location=GCP_US_CENTER1_LOCATION,
                    state="ACTIVE",
                    vpc_connector=None,
                )
            ]

            check = cloudfunction_function_inside_vpc()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Cloud Function fn-public is not connected to any VPC network."
            )
            assert result[0].resource_id == "fn-public"
            assert result[0].resource_name == "fn-public"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_function_with_empty_vpc_connector(self):
        cloudfunction_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                _CLIENT_PATH,
                new=cloudfunction_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_function_inside_vpc.cloudfunction_function_inside_vpc import (
                cloudfunction_function_inside_vpc,
            )
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_service import (
                Function,
            )

            cloudfunction_client.functions = [
                Function(
                    name="fn-empty",
                    project_id=GCP_PROJECT_ID,
                    location=GCP_US_CENTER1_LOCATION,
                    state="ACTIVE",
                    vpc_connector="",
                )
            ]

            check = cloudfunction_function_inside_vpc()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_inactive_function_skipped(self):
        cloudfunction_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                _CLIENT_PATH,
                new=cloudfunction_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_function_inside_vpc.cloudfunction_function_inside_vpc import (
                cloudfunction_function_inside_vpc,
            )
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_service import (
                Function,
            )

            cloudfunction_client.functions = [
                Function(
                    name="fn-deploy",
                    project_id=GCP_PROJECT_ID,
                    location=GCP_US_CENTER1_LOCATION,
                    state="DEPLOYING",
                    vpc_connector=None,
                )
            ]

            check = cloudfunction_function_inside_vpc()
            result = check.execute()
            assert len(result) == 0
