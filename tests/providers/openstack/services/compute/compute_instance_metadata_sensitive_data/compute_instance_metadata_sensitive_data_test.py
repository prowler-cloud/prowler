"""Tests for compute_instance_metadata_sensitive_data check."""

from unittest import mock

from prowler.lib.check.models import Severity
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
                metadata={"db_password": "Tr0ub4dor3xKq9vLmZ"},
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
                metadata={
                    "api_key": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
                },
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
                metadata={"db_url": "mysql://admin:s3cret@dbhost:3306/appdb"},
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
                metadata={
                    "ssh_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCUzlT9QGi8ZSr5\nk+LTRz/1TaiCCs6o1icW4cur0Q0hdBnbRJXUdjlQsgzmBvCBNkGHI8hb/RUPssvc\nDLU5kOQ3Wp2KgtbphhZ2PfpuJrzwHL1ejcJkRxegm/aTdmpoQKcxGeehAfHbmlLA\nxdfn6wPDfGji973yiRH56JRukJAaqF50HC2a/AVNC5HtZoVlbQ+WvVbYVUnPxNkv\nPpc53PjrBgWiTtdMONEqJ3jDiaqfUBt+TZYF0CFc9HgjnUniRX28OukDyLu+idOz\nFKyZxMXtqexkAvQLDW1PATpZgVQ7hJoCD8UVTXAtcgzPq5fA6AR2URiECHI6ZyL0\nUmixKfMNAgMBAAECggEAJRzp5wjdpmEgDQOkjpfGXJ6sAJUD8mmI8cTKeJWIzhdo\nDH8oVEdRJ65kl6lS6hMXWEZlJgYyrsnj3MPBnjQkKycbRCy6P59s8jwmfbsFI+iz\nFUZLXZm6i5jicGhYBRzc5hrlIYu73863RXOClAnSFDsu6K6rzfYASQFIJeRBwJfs\njqXinuun/h2zGjpiY+TtNsa8c+nC7f3sGsTzNJugDvBPWQzsnAMzXJqiyharre4V\no157XIOvdC0joIp8j/Ib1ZtMfz1K1LcgBgw0szSieIw0Rq8yQ0Ek7GtLh43jG+ap\nvcSEesTD1p4mjPXoWkPG8KYd4iwGedZaePfheVcKKQKBgQDNE03SWv18AH0d4fpB\nlFAtRybCfSvMORzBrt2oilz8wDmK+Zga5o+phCnM8v3eJy1v8BvIQ9RvwQA2uVgZ\nr701wNMpVrTsMujk83oVRhimZLk6Hyw07wmMgEHX7+izkm2Lk4Lk7Zol3VRfnWG6\nmIcUk7xB1yAs3mudsfx0VO0QyQKBgQC5wfdqCLj2hZk4sMZu8Bth+BHKChGItmDk\nAW7aNt+gaPyoryOJoi2OUO8ud8EyuqXiuslSk2pPtjvLhCppkoq6V8kmPAUzaxFk\n4nDEAxT9Un8IJ0j2ebv+koQKsBWjssbVSjrZgIcYIDK1QblgbCp2FSE3ima+V8ip\nOdNjiatWJQKBgEX8lox5nRSanhh6rIuA8DPjmmi5ix7xRs0avm7seXuQppK1R6G2\nmcTCY/mb2+Pa/vi6uuCHtZJGDaqfal+pyCr2GZp8CtapMS4hocJs37C5ozUguld+\nVIXsp4voRkQybsw5lWxHYloVxNu0vEuQDlmJabAWmNZ3OcbhnUSeTyFxAoGAFtkZ\n0owCHChwoT11Gt4jsBgwL/avE27DWigm92Y6eWOQeDsalupAyjmAQenu9Itqrgml\ni6egMu/KSQ0Xnmas86CqmC5XwWxQ9mS31BRA96u2/ky+t7pfej+RSDNCZiEuPbvk\noy4g78G+GvdbktWbH20X6dn3K0Bm6RG4w4yCa5UCgYBs0zAVs0DZmM8SUZJA/HuQ\nN6a1vKKns7xKw5N3SmX1KbDhx5LSZXfbUo2+QktE7iRf9G2f1o0q8kz9l/4AGXi1\nKJNUHupWoaQzGNrzAb27TUtFA0ocMG8KnqxjANWox5oPJS9OU5tw5H5dxeI/Senc\nkYW6eCnRzPcmBqex6Vuw4w==\n-----END PRIVATE KEY-----\n"
                },
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
                metadata={"admin_password": "Tr0ub4dor3xKq9vLmZ"},
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

    def test_instance_multiple_metadata_keys_correct_identification(self):
        """Test that secrets are correctly attributed to the right metadata keys."""
        compute_client = mock.MagicMock()
        compute_client.audit_config = {}
        compute_client.instances = [
            ComputeInstance(
                id="instance-7",
                name="Multiple Keys",
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
                metadata={
                    "environment": "production",
                    "application": "web-app",
                    "db_password": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                    "region": "us-east",
                },
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
            # Verify the secret is correctly attributed to 'db_password' key
            assert "in metadata key 'db_password'" in result[0].status_extended
            assert result[0].resource_id == "instance-7"

    def test_instance_metadata_key_ordering(self):
        """Test that secret detection works with different key orderings."""
        compute_client = mock.MagicMock()
        compute_client.audit_config = {}
        compute_client.instances = [
            ComputeInstance(
                id="instance-8",
                name="Ordered Keys",
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
                metadata={
                    "first_key": "safe_value",
                    "api_key": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                    "third_key": "also_safe",
                },
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
            # Verify the secret is correctly attributed to 'api_key' key (second in order)
            assert "in metadata key 'api_key'" in result[0].status_extended
            assert result[0].resource_id == "instance-8"

    def test_instance_verified_secret_escalates_to_critical(self):
        """Test that a confirmed live secret escalates the finding to CRITICAL (FAIL)."""
        compute_client = mock.MagicMock()
        compute_client.audit_config = {"secrets_validate": True}
        compute_client.instances = [
            ComputeInstance(
                id="instance-verified",
                name="Verified Secret",
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
                metadata={"api_key": "placeholder"},
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
            mock.patch(
                "prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data.detect_secrets_scan_batch",
                return_value={
                    0: [
                        {
                            "type": "JSON Web Token (base64url-encoded)",
                            "line_number": 2,
                            "filename": "data",
                            "hashed_secret": "x",
                            "is_verified": True,
                        }
                    ]
                },
            ) as mock_scan,
        ):
            from prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data import (
                compute_instance_metadata_sensitive_data,
            )

            check = compute_instance_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == Severity.critical
            assert "confirmed to be live" in result[0].status_extended
            assert mock_scan.call_args.kwargs.get("validate") is True

    def test_scan_failure_reports_manual(self):
        from prowler.lib.utils.utils import SecretsScanError

        compute_client = mock.MagicMock()
        compute_client.audit_config = {"secrets_ignore_patterns": []}
        compute_client.instances = [
            ComputeInstance(
                id="instance-scan-fail",
                name="Scan Fail",
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
                metadata={"api_key": "placeholder"},
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
            mock.patch(
                "prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data.detect_secrets_scan_batch",
                side_effect=SecretsScanError("Kingfisher exited with code 1"),
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_metadata_sensitive_data.compute_instance_metadata_sensitive_data import (
                compute_instance_metadata_sensitive_data,
            )

            check = compute_instance_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Could not scan" in result[0].status_extended
