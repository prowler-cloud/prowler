from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    set_mocked_gcp_provider,
)

_CHECK_PATH = (
    "prowler.providers.gcp.services.secretmanager."
    "secretmanager_secret_rotation_enabled."
    "secretmanager_secret_rotation_enabled"
)
_CLIENT_PATH = f"{_CHECK_PATH}.secretmanager_client"


def _secret_id(name: str) -> str:
    return f"projects/{GCP_PROJECT_ID}/secrets/{name}"


class Test_secretmanager_secret_rotation_enabled:
    def test_no_secrets(self):
        secretmanager_client = mock.MagicMock()
        secretmanager_client.audit_config = {"secretmanager_max_rotation_days": 90}

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
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_rotation_enabled.secretmanager_secret_rotation_enabled import (
                secretmanager_secret_rotation_enabled,
            )

            secretmanager_client.secrets = []

            check = secretmanager_secret_rotation_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_rotation_within_90_days_pass(self):
        secretmanager_client = mock.MagicMock()
        secretmanager_client.audit_config = {"secretmanager_max_rotation_days": 90}

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
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_rotation_enabled.secretmanager_secret_rotation_enabled import (
                secretmanager_secret_rotation_enabled,
            )
            from prowler.providers.gcp.services.secretmanager.secretmanager_service import (
                Secret,
            )

            secretmanager_client.secrets = [
                Secret(
                    id=_secret_id("secret-rotated"),
                    name="secret-rotated",
                    project_id=GCP_PROJECT_ID,
                    rotation_period="7776000s",
                )
            ]

            check = secretmanager_secret_rotation_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Secret secret-rotated has automatic rotation enabled with a period of 90 days."
            )
            assert result[0].resource_id == "secret-rotated"
            assert result[0].resource_name == "secret-rotated"
            assert result[0].location == "global"
            assert result[0].project_id == GCP_PROJECT_ID

    def test_rotation_period_exceeds_max_fail(self):
        secretmanager_client = mock.MagicMock()
        secretmanager_client.audit_config = {"secretmanager_max_rotation_days": 90}

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
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_rotation_enabled.secretmanager_secret_rotation_enabled import (
                secretmanager_secret_rotation_enabled,
            )
            from prowler.providers.gcp.services.secretmanager.secretmanager_service import (
                Secret,
            )

            secretmanager_client.secrets = [
                Secret(
                    id=_secret_id("secret-stale"),
                    name="secret-stale",
                    project_id=GCP_PROJECT_ID,
                    rotation_period="9504000s",
                )
            ]

            check = secretmanager_secret_rotation_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "exceeds the 90-day maximum" in result[0].status_extended
            assert result[0].resource_id == "secret-stale"

    def test_no_rotation_fail(self):
        secretmanager_client = mock.MagicMock()
        secretmanager_client.audit_config = {"secretmanager_max_rotation_days": 90}

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
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_rotation_enabled.secretmanager_secret_rotation_enabled import (
                secretmanager_secret_rotation_enabled,
            )
            from prowler.providers.gcp.services.secretmanager.secretmanager_service import (
                Secret,
            )

            secretmanager_client.secrets = [
                Secret(
                    id=_secret_id("secret-no-rotation"),
                    name="secret-no-rotation",
                    project_id=GCP_PROJECT_ID,
                    rotation_period=None,
                )
            ]

            check = secretmanager_secret_rotation_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Secret secret-no-rotation does not have automatic rotation enabled."
            )

    def test_fractional_seconds_period_pass(self):
        secretmanager_client = mock.MagicMock()
        secretmanager_client.audit_config = {"secretmanager_max_rotation_days": 90}

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
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_rotation_enabled.secretmanager_secret_rotation_enabled import (
                secretmanager_secret_rotation_enabled,
            )
            from prowler.providers.gcp.services.secretmanager.secretmanager_service import (
                Secret,
            )

            secretmanager_client.secrets = [
                Secret(
                    id=_secret_id("secret-fractional"),
                    name="secret-fractional",
                    project_id=GCP_PROJECT_ID,
                    rotation_period="2592000.500000000s",
                )
            ]

            check = secretmanager_secret_rotation_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_sub_day_rotation_period_pass(self):
        secretmanager_client = mock.MagicMock()
        secretmanager_client.audit_config = {"secretmanager_max_rotation_days": 90}

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
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_rotation_enabled.secretmanager_secret_rotation_enabled import (
                secretmanager_secret_rotation_enabled,
            )
            from prowler.providers.gcp.services.secretmanager.secretmanager_service import (
                Secret,
            )

            secretmanager_client.secrets = [
                Secret(
                    id=_secret_id("secret-sub-day"),
                    name="secret-sub-day",
                    project_id=GCP_PROJECT_ID,
                    rotation_period="3600s",
                )
            ]

            check = secretmanager_secret_rotation_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_overdue_next_rotation_fail(self):
        secretmanager_client = mock.MagicMock()
        secretmanager_client.audit_config = {"secretmanager_max_rotation_days": 90}

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
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_rotation_enabled.secretmanager_secret_rotation_enabled import (
                secretmanager_secret_rotation_enabled,
            )
            from prowler.providers.gcp.services.secretmanager.secretmanager_service import (
                Secret,
            )

            secretmanager_client.secrets = [
                Secret(
                    id=_secret_id("secret-overdue"),
                    name="secret-overdue",
                    project_id=GCP_PROJECT_ID,
                    rotation_period="7776000s",
                    next_rotation_time="2020-01-01T00:00:00Z",
                )
            ]

            check = secretmanager_secret_rotation_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "overdue" in result[0].status_extended

    def test_invalid_rotation_period_format_fail(self):
        """Unparseable rotation_period falls back to None → FAIL with no-rotation message."""
        secretmanager_client = mock.MagicMock()
        secretmanager_client.audit_config = {"secretmanager_max_rotation_days": 90}

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
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_rotation_enabled.secretmanager_secret_rotation_enabled import (
                secretmanager_secret_rotation_enabled,
            )
            from prowler.providers.gcp.services.secretmanager.secretmanager_service import (
                Secret,
            )

            secretmanager_client.secrets = [
                Secret(
                    id=_secret_id("secret-bad-period"),
                    name="secret-bad-period",
                    project_id=GCP_PROJECT_ID,
                    rotation_period="not-a-duration",
                )
            ]

            check = secretmanager_secret_rotation_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Secret secret-bad-period does not have automatic rotation enabled."
            )

    def test_invalid_next_rotation_time_fail_closed(self):
        """Unparseable next_rotation_time fails closed → FAIL as overdue."""
        secretmanager_client = mock.MagicMock()
        secretmanager_client.audit_config = {"secretmanager_max_rotation_days": 90}

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
            from prowler.providers.gcp.services.secretmanager.secretmanager_secret_rotation_enabled.secretmanager_secret_rotation_enabled import (
                secretmanager_secret_rotation_enabled,
            )
            from prowler.providers.gcp.services.secretmanager.secretmanager_service import (
                Secret,
            )

            secretmanager_client.secrets = [
                Secret(
                    id=_secret_id("secret-bad-timestamp"),
                    name="secret-bad-timestamp",
                    project_id=GCP_PROJECT_ID,
                    rotation_period="7776000s",
                    next_rotation_time="not-a-timestamp",
                )
            ]

            check = secretmanager_secret_rotation_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "overdue" in result[0].status_extended
