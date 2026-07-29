from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)

_CHECK_PATH = (
    "prowler.providers.gcp.services.cloudfunction."
    "cloudfunction_function_not_publicly_accessible."
    "cloudfunction_function_not_publicly_accessible"
)
_CLIENT_PATH = f"{_CHECK_PATH}.cloudfunction_client"


def _function_id(name: str) -> str:
    return (
        f"projects/{GCP_PROJECT_ID}/locations/{GCP_US_CENTER1_LOCATION}"
        f"/functions/{name}"
    )


class Test_cloudfunction_function_not_publicly_accessible:
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
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_function_not_publicly_accessible.cloudfunction_function_not_publicly_accessible import (
                cloudfunction_function_not_publicly_accessible,
            )

            cloudfunction_client.functions = []

            check = cloudfunction_function_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 0

    def test_function_private(self):
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
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_function_not_publicly_accessible.cloudfunction_function_not_publicly_accessible import (
                cloudfunction_function_not_publicly_accessible,
            )
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_service import (
                Function,
            )

            cloudfunction_client.functions = [
                Function(
                    id=_function_id("fn-private"),
                    name="fn-private",
                    project_id=GCP_PROJECT_ID,
                    location=GCP_US_CENTER1_LOCATION,
                    state="ACTIVE",
                    publicly_accessible=False,
                )
            ]

            check = cloudfunction_function_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Cloud Function fn-private is not publicly accessible."
            )
            assert result[0].resource_id == "fn-private"
            assert result[0].resource_name == "fn-private"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_function_publicly_accessible(self):
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
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_function_not_publicly_accessible.cloudfunction_function_not_publicly_accessible import (
                cloudfunction_function_not_publicly_accessible,
            )
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_service import (
                Function,
            )

            cloudfunction_client.functions = [
                Function(
                    id=_function_id("fn-public"),
                    name="fn-public",
                    project_id=GCP_PROJECT_ID,
                    location=GCP_US_CENTER1_LOCATION,
                    state="ACTIVE",
                    publicly_accessible=True,
                )
            ]

            check = cloudfunction_function_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "Cloud Function fn-public is publicly invocable "
                "(allUsers or allAuthenticatedUsers IAM binding detected)."
            )
            assert result[0].resource_id == "fn-public"
            assert result[0].resource_name == "fn-public"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_multiple_functions_mixed(self):
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
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_function_not_publicly_accessible.cloudfunction_function_not_publicly_accessible import (
                cloudfunction_function_not_publicly_accessible,
            )
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_service import (
                Function,
            )

            cloudfunction_client.functions = [
                Function(
                    id=_function_id("fn-private"),
                    name="fn-private",
                    project_id=GCP_PROJECT_ID,
                    location=GCP_US_CENTER1_LOCATION,
                    state="ACTIVE",
                    publicly_accessible=False,
                ),
                Function(
                    id=_function_id("fn-public"),
                    name="fn-public",
                    project_id=GCP_PROJECT_ID,
                    location=GCP_US_CENTER1_LOCATION,
                    state="ACTIVE",
                    publicly_accessible=True,
                ),
            ]

            check = cloudfunction_function_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 2

            by_id = {r.resource_id: r for r in result}
            assert by_id["fn-private"].status == "PASS"
            assert by_id["fn-public"].status == "FAIL"

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
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_function_not_publicly_accessible.cloudfunction_function_not_publicly_accessible import (
                cloudfunction_function_not_publicly_accessible,
            )
            from prowler.providers.gcp.services.cloudfunction.cloudfunction_service import (
                Function,
            )

            cloudfunction_client.functions = [
                Function(
                    id=_function_id("fn-deleting"),
                    name="fn-deleting",
                    project_id=GCP_PROJECT_ID,
                    location=GCP_US_CENTER1_LOCATION,
                    state="DELETING",
                    publicly_accessible=True,
                )
            ]

            check = cloudfunction_function_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 0
