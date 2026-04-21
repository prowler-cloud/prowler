from datetime import datetime, timedelta, timezone
from unittest import mock

from prowler.providers.oraclecloud.services.kms.kms_service import Key
from tests.providers.oraclecloud.oci_fixtures import (
    OCI_COMPARTMENT_ID,
    OCI_REGION,
    OCI_TENANCY_ID,
    set_mocked_oraclecloud_provider,
)

KEY_ID = "ocid1.key.oc1.iad.aaaaaaaexample"
KEY_NAME = "test-key"


class Test_kms_key_rotation_enabled:
    def test_no_keys(self):
        """No keys → empty findings."""
        kms_client = mock.MagicMock()
        kms_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        kms_client.audited_tenancy = OCI_TENANCY_ID
        kms_client.keys = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.kms.kms_key_rotation_enabled.kms_key_rotation_enabled.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.kms.kms_key_rotation_enabled.kms_key_rotation_enabled import (
                kms_key_rotation_enabled,
            )

            check = kms_key_rotation_enabled()
            result = check.execute()

            assert result == []

    def test_key_with_auto_rotation_enabled(self):
        """Key with auto-rotation enabled → PASS."""
        kms_client = mock.MagicMock()
        kms_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        kms_client.audited_tenancy = OCI_TENANCY_ID
        kms_client.keys = [
            Key(
                id=KEY_ID,
                name=KEY_NAME,
                compartment_id=OCI_COMPARTMENT_ID,
                region=OCI_REGION,
                lifecycle_state="ENABLED",
                is_auto_rotation_enabled=True,
                rotation_interval_in_days=90,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.kms.kms_key_rotation_enabled.kms_key_rotation_enabled.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.kms.kms_key_rotation_enabled.kms_key_rotation_enabled import (
                kms_key_rotation_enabled,
            )

            check = kms_key_rotation_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "auto-rotation enabled" in result[0].status_extended
            assert result[0].resource_id == KEY_ID
            assert result[0].resource_name == KEY_NAME
            assert result[0].region == OCI_REGION
            assert result[0].compartment_id == OCI_COMPARTMENT_ID

    def test_key_manually_rotated_within_365_days(self):
        """Key manually rotated within last 365 days (no auto-rotation) → PASS."""
        kms_client = mock.MagicMock()
        kms_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        kms_client.audited_tenancy = OCI_TENANCY_ID
        kms_client.keys = [
            Key(
                id=KEY_ID,
                name=KEY_NAME,
                compartment_id=OCI_COMPARTMENT_ID,
                region=OCI_REGION,
                lifecycle_state="ENABLED",
                is_auto_rotation_enabled=False,
                rotation_interval_in_days=None,
                current_key_version_time_created=datetime.now(timezone.utc)
                - timedelta(days=100),
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.kms.kms_key_rotation_enabled.kms_key_rotation_enabled.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.kms.kms_key_rotation_enabled.kms_key_rotation_enabled import (
                kms_key_rotation_enabled,
            )

            check = kms_key_rotation_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "manually rotated" in result[0].status_extended
            assert result[0].resource_id == KEY_ID

    def test_key_manually_rotated_over_365_days_ago(self):
        """Key manually rotated more than 365 days ago (no auto-rotation) → FAIL."""
        kms_client = mock.MagicMock()
        kms_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        kms_client.audited_tenancy = OCI_TENANCY_ID
        kms_client.keys = [
            Key(
                id=KEY_ID,
                name=KEY_NAME,
                compartment_id=OCI_COMPARTMENT_ID,
                region=OCI_REGION,
                lifecycle_state="ENABLED",
                is_auto_rotation_enabled=False,
                rotation_interval_in_days=None,
                current_key_version_time_created=datetime.now(timezone.utc)
                - timedelta(days=400),
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.kms.kms_key_rotation_enabled.kms_key_rotation_enabled.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.kms.kms_key_rotation_enabled.kms_key_rotation_enabled import (
                kms_key_rotation_enabled,
            )

            check = kms_key_rotation_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not been rotated" in result[0].status_extended
            assert result[0].resource_id == KEY_ID

    def test_key_no_rotation_at_all(self):
        """Key with no auto-rotation and no version info → FAIL."""
        kms_client = mock.MagicMock()
        kms_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        kms_client.audited_tenancy = OCI_TENANCY_ID
        kms_client.keys = [
            Key(
                id=KEY_ID,
                name=KEY_NAME,
                compartment_id=OCI_COMPARTMENT_ID,
                region=OCI_REGION,
                lifecycle_state="ENABLED",
                is_auto_rotation_enabled=False,
                rotation_interval_in_days=None,
                current_key_version_time_created=None,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.kms.kms_key_rotation_enabled.kms_key_rotation_enabled.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.kms.kms_key_rotation_enabled.kms_key_rotation_enabled import (
                kms_key_rotation_enabled,
            )

            check = kms_key_rotation_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not been rotated" in result[0].status_extended
            assert result[0].resource_id == KEY_ID
