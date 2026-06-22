from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    set_mocked_gcp_provider,
)

_CHECK_PATH = (
    "prowler.providers.gcp.services.secretmanager."
    "secretmanager_secret_not_publicly_accessible."
    "secretmanager_secret_not_publicly_accessible"
)
_CLIENT_PATH = f"{_CHECK_PATH}.secretmanager_client"


def _secret_id(name: str) -> str:
    return f"projects/{GCP_PROJECT_ID}/secrets/{name}"


class Test_secretmanager_secret_not_publicly_accessible:
    def test_no_secrets(self):
        secretmanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                _CLIENT_PATH,
                new=secretmanager_client,
            ),
        ):
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_not_publicly_accessible.secretmanager_secret_not_publicly_accessible import (
                secretmanager_secret_not_publicly_accessible,
            )

            secretmanager_client.secrets = []

            check = secretmanager_secret_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 0

    def test_secret_private(self):
        secretmanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                _CLIENT_PATH,
                new=secretmanager_client,
            ),
        ):
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_not_publicly_accessible.secretmanager_secret_not_publicly_accessible import (
                secretmanager_secret_not_publicly_accessible,
            )
            from prowler.providers.gcp.services.secretmanager.secretmanager_service import (
                Secret,
            )

            secretmanager_client.secrets = [
                Secret(
                    id=_secret_id("secret-private"),
                    name="secret-private",
                    project_id=GCP_PROJECT_ID,
                    publicly_accessible=False,
                )
            ]

            check = secretmanager_secret_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Secret secret-private is not publicly accessible."
            )
            assert result[0].resource_id == "secret-private"
            assert result[0].resource_name == "secret-private"
            assert result[0].location == "global"
            assert result[0].project_id == GCP_PROJECT_ID

    def test_secret_publicly_accessible(self):
        secretmanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                _CLIENT_PATH,
                new=secretmanager_client,
            ),
        ):
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_not_publicly_accessible.secretmanager_secret_not_publicly_accessible import (
                secretmanager_secret_not_publicly_accessible,
            )
            from prowler.providers.gcp.services.secretmanager.secretmanager_service import (
                Secret,
            )

            secretmanager_client.secrets = [
                Secret(
                    id=_secret_id("secret-public"),
                    name="secret-public",
                    project_id=GCP_PROJECT_ID,
                    publicly_accessible=True,
                )
            ]

            check = secretmanager_secret_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "Secret secret-public is publicly accessible "
                "(allUsers or allAuthenticatedUsers IAM binding detected)."
            )
            assert result[0].resource_id == "secret-public"
            assert result[0].resource_name == "secret-public"
            assert result[0].location == "global"
            assert result[0].project_id == GCP_PROJECT_ID

    def test_multiple_secrets_mixed(self):
        secretmanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                _CLIENT_PATH,
                new=secretmanager_client,
            ),
        ):
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_not_publicly_accessible.secretmanager_secret_not_publicly_accessible import (
                secretmanager_secret_not_publicly_accessible,
            )
            from prowler.providers.gcp.services.secretmanager.secretmanager_service import (
                Secret,
            )

            secretmanager_client.secrets = [
                Secret(
                    id=_secret_id("secret-private"),
                    name="secret-private",
                    project_id=GCP_PROJECT_ID,
                    publicly_accessible=False,
                ),
                Secret(
                    id=_secret_id("secret-public"),
                    name="secret-public",
                    project_id=GCP_PROJECT_ID,
                    publicly_accessible=True,
                ),
            ]

            check = secretmanager_secret_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 2

            by_id = {r.resource_id: r for r in result}
            assert by_id["secret-private"].status == "PASS"
            assert by_id["secret-public"].status == "FAIL"
