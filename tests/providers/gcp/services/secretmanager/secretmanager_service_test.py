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

    # _get_secrets
    client.projects().secrets().list().execute.return_value = {
        "secrets": secrets_list
    }
    client.projects().secrets().list_next.return_value = None

    # _get_secret_iam_policy — called per-secret via threading_call
    iam_response = {"bindings": iam_bindings or []}

    def mock_get_iam_policy(resource):
        rv = MagicMock()
        rv.execute.return_value = iam_response
        return rv

    client.projects().secrets().getIamPolicy = mock_get_iam_policy

    return client


class TestSecretManagerService:
    def test_get_secrets_with_rotation(self):
        """Service parses rotation_period and next_rotation_time from the API response."""

        def mock_api_client_with_rotation(*args, **kwargs):
            return _make_secretmanager_client(
                secrets_list=[
                    {
                        "name": f"projects/{GCP_PROJECT_ID}/secrets/secret-with-rotation",
                        "rotation": {
                            "rotationPeriod": "7776000s",
                            "nextRotationTime": "2025-07-01T00:00:00Z",
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
                new=mock_api_client_with_rotation,
            ),
        ):
            sm_client = SecretManager(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert len(sm_client.secrets) == 1
            assert sm_client.secrets[0].name == "secret-with-rotation"
            assert (
                sm_client.secrets[0].id
                == f"projects/{GCP_PROJECT_ID}/secrets/secret-with-rotation"
            )
            assert sm_client.secrets[0].rotation_period == "7776000s"
            assert sm_client.secrets[0].next_rotation_time == "2025-07-01T00:00:00Z"
            assert sm_client.secrets[0].project_id == GCP_PROJECT_ID
            assert sm_client.secrets[0].publicly_accessible is False

    def test_get_secrets_without_rotation(self):
        """Service sets rotation_period=None when no rotation key is present."""

        def mock_api_client_no_rotation(*args, **kwargs):
            return _make_secretmanager_client(
                secrets_list=[
                    {
                        "name": f"projects/{GCP_PROJECT_ID}/secrets/secret-no-rotation",
                        # no 'rotation' key at all
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
                new=mock_api_client_no_rotation,
            ),
        ):
            sm_client = SecretManager(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert len(sm_client.secrets) == 1
            assert sm_client.secrets[0].name == "secret-no-rotation"
            assert sm_client.secrets[0].rotation_period is None
            assert sm_client.secrets[0].next_rotation_time is None
            assert sm_client.secrets[0].publicly_accessible is False

    def test_get_secrets_iam_policy_public(self):
        """_get_secrets_iam_policy sets publicly_accessible=True when allUsers binding found."""

        def mock_api_client_public_iam(*args, **kwargs):
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
                new=mock_api_client_public_iam,
            ),
        ):
            sm_client = SecretManager(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert len(sm_client.secrets) == 1
            assert sm_client.secrets[0].name == "public-secret"
            assert sm_client.secrets[0].publicly_accessible is True

    def test_get_secrets_iam_policy_not_public(self):
        """_get_secrets_iam_policy leaves publicly_accessible=False when no public members."""

        def mock_api_client_private_iam(*args, **kwargs):
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
                new=mock_api_client_private_iam,
            ),
        ):
            sm_client = SecretManager(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert len(sm_client.secrets) == 1
            assert sm_client.secrets[0].name == "private-secret"
            assert sm_client.secrets[0].publicly_accessible is False
