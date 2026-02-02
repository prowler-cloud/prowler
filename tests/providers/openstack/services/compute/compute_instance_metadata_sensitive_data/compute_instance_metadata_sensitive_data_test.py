"""Tests for compute_instance_metadata_sensitive_data check."""

from unittest import mock

from prowler.providers.openstack.services.compute.compute_service import ComputeInstance
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_compute_instance_metadata_sensitive_data:
    """Test suite for compute_instance_metadata_sensitive_data check."""

    def test_no_instances(self):
        """Test when no instances exist."""
        compute_client = mock.MagicMock()
        compute_client.instances = []
        compute_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data import (
                compute_instance_metadata_sensitive_data,
            )

            check = compute_instance_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 0

    def test_instance_no_metadata(self):
        """Test instance with no metadata (PASS)."""
        compute_client = mock.MagicMock()
        compute_client.audit_config = {}
        compute_client.instances = [
            ComputeInstance(
                id="instance-1",
                name="No Metadata",
                status="ACTIVE",
                flavor_id="flavor-1",
                security_groups=["default"],
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                is_locked=False,
                locked_reason="",
                key_name="",
                user_id="",
                access_ipv4="",
                access_ipv6="",
                public_v4="",
                public_v6="",
                private_v4="",
                private_v6="",
                networks={},
                has_config_drive=False,
                metadata={},
                user_data="",
                trusted_image_certificates=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data import (
                compute_instance_metadata_sensitive_data,
            )

            check = compute_instance_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Instance No Metadata (instance-1) has no metadata (no sensitive data exposure risk)."
            )
            assert result[0].resource_id == "instance-1"
            assert result[0].resource_name == "No Metadata"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_instance_safe_metadata(self):
        """Test instance with safe metadata (PASS)."""
        compute_client = mock.MagicMock()
        compute_client.audit_config = {}
        compute_client.instances = [
            ComputeInstance(
                id="instance-2",
                name="Safe Metadata",
                status="ACTIVE",
                flavor_id="flavor-1",
                security_groups=["default"],
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                is_locked=False,
                locked_reason="",
                key_name="",
                user_id="",
                access_ipv4="",
                access_ipv6="",
                public_v4="",
                public_v6="",
                private_v4="",
                private_v6="",
                networks={},
                has_config_drive=False,
                metadata={"environment": "production", "application": "web-app"},
                user_data="",
                trusted_image_certificates=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data import (
                compute_instance_metadata_sensitive_data,
            )

            check = compute_instance_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Instance Safe Metadata (instance-2) metadata does not contain sensitive data."
            )
            assert result[0].resource_id == "instance-2"
            assert result[0].resource_name == "Safe Metadata"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_instance_password_in_metadata(self):
        """Test instance with password in metadata (FAIL)."""
        compute_client = mock.MagicMock()
        compute_client.audit_config = {}
        compute_client.instances = [
            ComputeInstance(
                id="instance-3",
                name="Password Metadata",
                status="ACTIVE",
                flavor_id="flavor-1",
                security_groups=["default"],
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                is_locked=False,
                locked_reason="",
                key_name="",
                user_id="",
                access_ipv4="",
                access_ipv6="",
                public_v4="",
                public_v6="",
                private_v4="",
                private_v6="",
                networks={},
                has_config_drive=False,
                metadata={"db_password": "supersecret123"},
                user_data="",
                trusted_image_certificates=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data import (
                compute_instance_metadata_sensitive_data,
            )

            check = compute_instance_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "contains potential secrets" in result[0].status_extended

    def test_instance_api_key_in_metadata(self):
        """Test instance with API key in metadata (FAIL)."""
        compute_client = mock.MagicMock()
        compute_client.audit_config = {}
        compute_client.instances = [
            ComputeInstance(
                id="instance-4",
                name="API Key Metadata",
                status="ACTIVE",
                flavor_id="flavor-1",
                security_groups=["default"],
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                is_locked=False,
                locked_reason="",
                key_name="",
                user_id="",
                access_ipv4="",
                access_ipv6="",
                public_v4="",
                public_v6="",
                private_v4="",
                private_v6="",
                networks={},
                has_config_drive=False,
                metadata={"api_key": "sk-1234567890"},
                user_data="",
                trusted_image_certificates=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data import (
                compute_instance_metadata_sensitive_data,
            )

            check = compute_instance_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended.startswith(
                "Instance API Key Metadata (instance-4) metadata contains potential secrets ->"
            )
            assert result[0].resource_id == "instance-4"
            assert result[0].resource_name == "API Key Metadata"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_instance_connection_string_in_metadata(self):
        """Test instance with database connection string in metadata (FAIL)."""
        compute_client = mock.MagicMock()
        compute_client.audit_config = {}
        compute_client.instances = [
            ComputeInstance(
                id="instance-5",
                name="Connection String",
                status="ACTIVE",
                flavor_id="flavor-1",
                security_groups=["default"],
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                is_locked=False,
                locked_reason="",
                key_name="",
                user_id="",
                access_ipv4="",
                access_ipv6="",
                public_v4="",
                public_v6="",
                private_v4="",
                private_v6="",
                networks={},
                has_config_drive=False,
                metadata={"db_url": "postgresql://user:pass@host/db"},
                user_data="",
                trusted_image_certificates=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data import (
                compute_instance_metadata_sensitive_data,
            )

            check = compute_instance_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended.startswith(
                "Instance Connection String (instance-5) metadata contains potential secrets ->"
            )
            assert result[0].resource_id == "instance-5"
            assert result[0].resource_name == "Connection String"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_instance_private_key_in_metadata(self):
        """Test instance with private key in metadata (FAIL)."""
        compute_client = mock.MagicMock()
        compute_client.audit_config = {}
        compute_client.instances = [
            ComputeInstance(
                id="instance-6",
                name="Private Key",
                status="ACTIVE",
                flavor_id="flavor-1",
                security_groups=["default"],
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                is_locked=False,
                locked_reason="",
                key_name="",
                user_id="",
                access_ipv4="",
                access_ipv6="",
                public_v4="",
                public_v6="",
                private_v4="",
                private_v6="",
                networks={},
                has_config_drive=False,
                metadata={"ssh_key": "-----BEGIN RSA PRIVATE KEY-----"},
                user_data="",
                trusted_image_certificates=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data import (
                compute_instance_metadata_sensitive_data,
            )

            check = compute_instance_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended.startswith(
                "Instance Private Key (instance-6) metadata contains potential secrets ->"
            )
            assert result[0].resource_id == "instance-6"
            assert result[0].resource_name == "Private Key"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_multiple_instances_mixed(self):
        """Test multiple instances with mixed metadata."""
        compute_client = mock.MagicMock()
        compute_client.audit_config = {}
        compute_client.instances = [
            ComputeInstance(
                id="instance-pass",
                name="Safe",
                status="ACTIVE",
                flavor_id="flavor-1",
                security_groups=[],
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                is_locked=False,
                locked_reason="",
                key_name="",
                user_id="",
                access_ipv4="",
                access_ipv6="",
                public_v4="",
                public_v6="",
                private_v4="",
                private_v6="",
                networks={},
                has_config_drive=False,
                metadata={"tier": "web"},
                user_data="",
                trusted_image_certificates=[],
            ),
            ComputeInstance(
                id="instance-fail",
                name="Unsafe",
                status="ACTIVE",
                flavor_id="flavor-1",
                security_groups=[],
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                is_locked=False,
                locked_reason="",
                key_name="",
                user_id="",
                access_ipv4="",
                access_ipv6="",
                public_v4="",
                public_v6="",
                private_v4="",
                private_v6="",
                networks={},
                has_config_drive=False,
                metadata={"admin_password": "secret123"},
                user_data="",
                trusted_image_certificates=[],
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data import (
                compute_instance_metadata_sensitive_data,
            )

            check = compute_instance_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1
