from unittest.mock import MagicMock, patch

from prowler.providers.gcp.services.secretmanager.secretmanager_service import (
    SecretManager,
)
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


def _make_secretmanager_client(secrets_list, iam_bindings=None):
    """Return a mock GCP API client for the Secret Manager service."""
    client = MagicMock()

    client.projects().secrets().list().execute.return_value = {"secrets": secrets_list}
    client.projects().secrets().list_next.return_value = None

    iam_response = {"bindings": iam_bindings or []}

    def mock_get_iam_policy(resource):
        rv = MagicMock()
        rv.execute.return_value = iam_response
        return rv

    client.projects().secrets().getIamPolicy = mock_get_iam_policy

    return client


class TestSecretManagerService:
    def test_get_secrets(self):
        def mock_api_client(*args, **kwargs):
            return _make_secretmanager_client(
                secrets_list=[
                    {
                        "name": f"projects/{GCP_PROJECT_ID}/secrets/my-secret",
                    }
                ]
            )

        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                new=mock_api_client,
            ),
        ):
            sm_client = SecretManager(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert len(sm_client.secrets) == 1
            secret = sm_client.secrets[0]
            assert secret.name == "my-secret"
            assert secret.id == f"projects/{GCP_PROJECT_ID}/secrets/my-secret"
            assert secret.project_id == GCP_PROJECT_ID
            assert secret.location == "global"
            assert secret.rotation_period is None
            assert secret.next_rotation_time is None
            assert secret.publicly_accessible is False

    def test_get_secrets_with_rotation(self):
        def mock_api_client(*args, **kwargs):
            return _make_secretmanager_client(
                secrets_list=[
                    {
                        "name": f"projects/{GCP_PROJECT_ID}/secrets/secret-with-rotation",
                        "rotation": {
                            "rotationPeriod": "7776000s",
                            "nextRotationTime": "2026-09-01T00:00:00Z",
                        },
                    }
                ]
            )

        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                new=mock_api_client,
            ),
        ):
            sm_client = SecretManager(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert len(sm_client.secrets) == 1
            secret = sm_client.secrets[0]
            assert secret.name == "secret-with-rotation"
            assert secret.rotation_period == "7776000s"
            assert secret.next_rotation_time == "2026-09-01T00:00:00Z"

    def test_get_secrets_with_null_rotation(self):
        """API returning explicit `rotation: null` must not break enumeration."""

        def mock_api_client(*args, **kwargs):
            return _make_secretmanager_client(
                secrets_list=[
                    {
                        "name": f"projects/{GCP_PROJECT_ID}/secrets/null-rotation",
                        "rotation": None,
                    }
                ]
            )

        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                new=mock_api_client,
            ),
        ):
            sm_client = SecretManager(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert len(sm_client.secrets) == 1
            secret = sm_client.secrets[0]
            assert secret.name == "null-rotation"
            assert secret.rotation_period is None
            assert secret.next_rotation_time is None

    def test_get_secrets_iam_policy_all_users(self):
        def mock_api_client(*args, **kwargs):
            return _make_secretmanager_client(
                secrets_list=[
                    {
                        "name": f"projects/{GCP_PROJECT_ID}/secrets/public-secret",
                    }
                ],
                iam_bindings=[
                    {
                        "role": "roles/secretmanager.secretAccessor",
                        "members": ["allUsers"],
                    }
                ],
            )

        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                new=mock_api_client,
            ),
        ):
            sm_client = SecretManager(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert len(sm_client.secrets) == 1
            assert sm_client.secrets[0].publicly_accessible is True

    def test_get_secrets_iam_policy_all_authenticated_users(self):
        def mock_api_client(*args, **kwargs):
            return _make_secretmanager_client(
                secrets_list=[
                    {
                        "name": f"projects/{GCP_PROJECT_ID}/secrets/auth-users-secret",
                    }
                ],
                iam_bindings=[
                    {
                        "role": "roles/secretmanager.secretAccessor",
                        "members": ["allAuthenticatedUsers"],
                    }
                ],
            )

        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                new=mock_api_client,
            ),
        ):
            sm_client = SecretManager(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert len(sm_client.secrets) == 1
            assert sm_client.secrets[0].publicly_accessible is True

    def test_get_secrets_iam_policy_not_public(self):
        def mock_api_client(*args, **kwargs):
            return _make_secretmanager_client(
                secrets_list=[
                    {
                        "name": f"projects/{GCP_PROJECT_ID}/secrets/private-secret",
                    }
                ],
                iam_bindings=[
                    {
                        "role": "roles/secretmanager.secretAccessor",
                        "members": ["user:alice@example.com"],
                    }
                ],
            )

        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                new=mock_api_client,
            ),
        ):
            sm_client = SecretManager(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert len(sm_client.secrets) == 1
            assert sm_client.secrets[0].publicly_accessible is False
