from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)


class Test_kms_key_not_publicly_accessible_gcp:
    def test_kms_no_key(self):
        kms_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible.kms_client",
            new=kms_client,
        ):
            from prowler.providers.gcp.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible import (
                kms_key_not_publicly_accessible,
            )

            kms_client.project_ids = [GCP_PROJECT_ID]
            kms_client.region = GCP_US_CENTER1_LOCATION
            kms_client.crypto_keys = []

            check = kms_key_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 0

    def test_kms_key_public(self):
        kms_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible.kms_client",
            new=kms_client,
        ):
            from prowler.providers.gcp.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible import (
                kms_key_not_publicly_accessible,
            )
            from prowler.providers.gcp.services.kms.kms_service import (
                CriptoKey,
                KeyLocation,
                KeyRing,
            )

            kms_client.project_ids = [GCP_PROJECT_ID]
            kms_client.region = GCP_US_CENTER1_LOCATION

            keyring = KeyRing(
                name="projects/123/locations/us-central1/keyRings/keyring1",
                project_id=GCP_PROJECT_ID,
            )

            keylocation = KeyLocation(
                name=GCP_US_CENTER1_LOCATION,
                project_id=GCP_PROJECT_ID,
            )

            kms_client.crypto_keys = [
                CriptoKey(
                    name="key1",
                    id="projects/123/locations/us-central1/keyRings/keyring1/cryptoKeys/key1",
                    project_id=GCP_PROJECT_ID,
                    rotation_period="7776000s",
                    next_rotation_time="2021-01-01T00:00:00Z",
                    key_ring=keyring.name,
                    location=keylocation.name,
                    members=["allUsers"],
                )
            ]

            check = kms_key_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Key {kms_client.crypto_keys[0].name} may be publicly accessible."
            )
            assert result[0].resource_id == kms_client.crypto_keys[0].id
            assert result[0].resource_name == kms_client.crypto_keys[0].name
            assert result[0].location == kms_client.crypto_keys[0].location
            assert result[0].project_id == kms_client.crypto_keys[0].project_id

    def test_kms_key_private(self):
        kms_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible.kms_client",
            new=kms_client,
        ):
            from prowler.providers.gcp.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible import (
                kms_key_not_publicly_accessible,
            )
            from prowler.providers.gcp.services.kms.kms_service import (
                CriptoKey,
                KeyLocation,
                KeyRing,
            )

            kms_client.project_ids = [GCP_PROJECT_ID]
            kms_client.region = GCP_US_CENTER1_LOCATION

            keyring = KeyRing(
                name="projects/123/locations/us-central1/keyRings/keyring1",
                project_id=GCP_PROJECT_ID,
            )

            keylocation = KeyLocation(
                name=GCP_US_CENTER1_LOCATION,
                project_id=GCP_PROJECT_ID,
            )

            kms_client.crypto_keys = [
                CriptoKey(
                    name="key1",
                    id="projects/123/locations/us-central1/keyRings/keyring1/cryptoKeys/key1",
                    project_id=GCP_PROJECT_ID,
                    rotation_period="7776000s",
                    next_rotation_time="2021-01-01T00:00:00Z",
                    key_ring=keyring.name,
                    location=keylocation.name,
                    members=["user:jane@example.com"],
                )
            ]

            check = kms_key_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Key {kms_client.crypto_keys[0].name} is not exposed to Public."
            )
            assert result[0].resource_id == kms_client.crypto_keys[0].id
            assert result[0].resource_name == kms_client.crypto_keys[0].name
            assert result[0].location == kms_client.crypto_keys[0].location
            assert result[0].project_id == kms_client.crypto_keys[0].project_id

    def test_kms_key_no_member(self):
        kms_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible.kms_client",
            new=kms_client,
        ):
            from prowler.providers.gcp.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible import (
                kms_key_not_publicly_accessible,
            )
            from prowler.providers.gcp.services.kms.kms_service import (
                CriptoKey,
                KeyLocation,
                KeyRing,
            )

            kms_client.project_ids = [GCP_PROJECT_ID]
            kms_client.region = GCP_US_CENTER1_LOCATION

            keyring = KeyRing(
                name="projects/123/locations/us-central1/keyRings/keyring1",
                project_id=GCP_PROJECT_ID,
            )

            keylocation = KeyLocation(
                name=GCP_US_CENTER1_LOCATION,
                project_id=GCP_PROJECT_ID,
            )

            kms_client.crypto_keys = [
                CriptoKey(
                    name="key1",
                    id="projects/123/locations/us-central1/keyRings/keyring1/cryptoKeys/key1",
                    project_id=GCP_PROJECT_ID,
                    rotation_period="7776000s",
                    next_rotation_time="2021-01-01T00:00:00Z",
                    key_ring=keyring.name,
                    location=keylocation.name,
                    members=[],
                )
            ]

            check = kms_key_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Key {kms_client.crypto_keys[0].name} is not exposed to Public."
            )
            assert result[0].resource_id == kms_client.crypto_keys[0].id
            assert result[0].resource_name == kms_client.crypto_keys[0].name
            assert result[0].location == kms_client.crypto_keys[0].location
            assert result[0].project_id == kms_client.crypto_keys[0].project_id
