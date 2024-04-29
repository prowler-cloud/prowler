from unittest.mock import patch

from prowler.providers.gcp.services.kms.kms_service import KMS
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_api_client,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


class TestKMSService:
    def test_service(self):
        with patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
            new=mock_is_api_active,
        ), patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
            new=mock_api_client,
        ):
            kms_client = KMS(set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID]))
            assert kms_client.service == "cloudkms"
            assert kms_client.project_ids == [GCP_PROJECT_ID]

            assert len(kms_client.locations) == 1
            assert kms_client.locations[0].name == "eu-west1"
            assert kms_client.locations[0].project_id == GCP_PROJECT_ID

            assert len(kms_client.key_rings) == 2
            assert (
                kms_client.key_rings[0].name
                == "projects/123/locations/eu-west1/keyRings/keyring1"
            )
            assert kms_client.key_rings[0].project_id == GCP_PROJECT_ID
            assert (
                kms_client.key_rings[1].name
                == "projects/123/locations/eu-west1/keyRings/keyring2"
            )
            assert kms_client.key_rings[1].project_id == GCP_PROJECT_ID

            assert len(kms_client.crypto_keys) == 2
            assert kms_client.crypto_keys[0].name == "key1"
            assert kms_client.crypto_keys[0].location == "eu-west1"
            assert (
                kms_client.crypto_keys[0].key_ring
                == "projects/123/locations/eu-west1/keyRings/keyring1"
            )
            assert kms_client.crypto_keys[0].rotation_period == "7776000s"
            assert kms_client.crypto_keys[0].members == [
                "user:mike@example.com",
                "group:admins@example.com",
                "domain:google.com",
                "serviceAccount:my-project-id@appspot.gserviceaccount.com",
            ]
            assert kms_client.crypto_keys[0].project_id == GCP_PROJECT_ID
            assert kms_client.crypto_keys[1].name == "key2"
            assert kms_client.crypto_keys[1].location == "eu-west1"
            assert (
                kms_client.crypto_keys[1].key_ring
                == "projects/123/locations/eu-west1/keyRings/keyring1"
            )
            assert kms_client.crypto_keys[1].members == []
            assert kms_client.crypto_keys[1].project_id == GCP_PROJECT_ID
