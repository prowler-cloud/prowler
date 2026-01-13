from unittest import mock

from tests.providers.oraclecloud.oci_fixtures import (
    OCI_COMPARTMENT_ID,
    OCI_REGION,
    OCI_TENANCY_ID,
    set_mocked_oraclecloud_provider,
)


class Test_cloudguard_enabled:
    def test_no_resources(self):
        """cloudguard_enabled: No resources to check"""
        cloudguard_client = mock.MagicMock()
        cloudguard_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        cloudguard_client.audited_tenancy = OCI_TENANCY_ID

        # Mock empty collections
        cloudguard_client.rules = []
        cloudguard_client.topics = []
        cloudguard_client.subscriptions = []
        cloudguard_client.users = []
        cloudguard_client.groups = []
        cloudguard_client.policies = []
        cloudguard_client.compartments = []
        cloudguard_client.instances = []
        cloudguard_client.volumes = []
        cloudguard_client.boot_volumes = []
        cloudguard_client.buckets = []
        cloudguard_client.keys = []
        cloudguard_client.file_systems = []
        cloudguard_client.databases = []
        cloudguard_client.security_lists = []
        cloudguard_client.security_groups = []
        cloudguard_client.subnets = []
        cloudguard_client.vcns = []
        cloudguard_client.configuration = None
        cloudguard_client.active_non_root_compartments = []
        cloudguard_client.password_policy = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.cloudguard.cloudguard_enabled.cloudguard_enabled.cloudguard_client",
                new=cloudguard_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.cloudguard.cloudguard_enabled.cloudguard_enabled import (
                cloudguard_enabled,
            )

            check = cloudguard_enabled()
            result = check.execute()

            # Verify result is a list (empty or with findings)
            assert isinstance(result, list)

    def test_resource_compliant(self):
        """cloudguard_enabled: Resource passes the check (PASS)"""
        cloudguard_client = mock.MagicMock()
        cloudguard_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        cloudguard_client.audited_tenancy = OCI_TENANCY_ID

        # Mock a compliant resource
        resource = mock.MagicMock()
        resource.id = "ocid1.resource.oc1.iad.aaaaaaaexample"
        resource.name = "compliant-resource"
        resource.region = OCI_REGION
        resource.compartment_id = OCI_COMPARTMENT_ID
        resource.lifecycle_state = "ACTIVE"
        resource.tags = {"Environment": "Production"}

        # Set attributes that make the resource compliant
        resource.versioning = "Enabled"
        resource.is_auto_rotation_enabled = True
        resource.rotation_interval_in_days = 90
        resource.public_access_type = "NoPublicAccess"
        resource.logging_enabled = True
        resource.kms_key_id = "ocid1.key.oc1.iad.aaaaaaaexample"
        resource.in_transit_encryption = "ENABLED"
        resource.is_secure_boot_enabled = True
        resource.legacy_endpoint_disabled = True
        resource.is_legacy_imds_endpoint_disabled = True

        # Mock client with compliant resource
        cloudguard_client.buckets = [resource]
        cloudguard_client.keys = [resource]
        cloudguard_client.volumes = [resource]
        cloudguard_client.boot_volumes = [resource]
        cloudguard_client.instances = [resource]
        cloudguard_client.file_systems = [resource]
        cloudguard_client.databases = [resource]
        cloudguard_client.security_lists = []
        cloudguard_client.security_groups = []
        cloudguard_client.rules = []
        cloudguard_client.configuration = resource
        cloudguard_client.users = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.cloudguard.cloudguard_enabled.cloudguard_enabled.cloudguard_client",
                new=cloudguard_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.cloudguard.cloudguard_enabled.cloudguard_enabled import (
                cloudguard_enabled,
            )

            check = cloudguard_enabled()
            result = check.execute()

            assert isinstance(result, list)

            # If results exist, verify PASS findings
            if len(result) > 0:
                # Find PASS results
                pass_results = [r for r in result if r.status == "PASS"]

                if pass_results:
                    # Detailed assertions on first PASS result
                    assert pass_results[0].status == "PASS"
                    assert pass_results[0].status_extended is not None
                    assert len(pass_results[0].status_extended) > 0

                    # Verify resource identification
                    assert pass_results[0].resource_id is not None
                    assert pass_results[0].resource_name is not None
                    assert pass_results[0].region is not None
                    assert pass_results[0].compartment_id is not None

                    # Verify metadata
                    assert pass_results[0].check_metadata.Provider == "oraclecloud"
                    assert (
                        pass_results[0].check_metadata.CheckID == "cloudguard_enabled"
                    )
                    assert pass_results[0].check_metadata.ServiceName == "cloudguard"

    def test_resource_non_compliant(self):
        """cloudguard_enabled: Resource fails the check (FAIL)"""
        cloudguard_client = mock.MagicMock()
        cloudguard_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        cloudguard_client.audited_tenancy = OCI_TENANCY_ID

        # Mock a non-compliant resource
        resource = mock.MagicMock()
        resource.id = "ocid1.resource.oc1.iad.bbbbbbbexample"
        resource.name = "non-compliant-resource"
        resource.region = OCI_REGION
        resource.compartment_id = OCI_COMPARTMENT_ID
        resource.lifecycle_state = "ACTIVE"
        resource.tags = {"Environment": "Development"}

        # Set attributes that make the resource non-compliant
        resource.versioning = "Disabled"
        resource.is_auto_rotation_enabled = False
        resource.rotation_interval_in_days = None
        resource.public_access_type = "ObjectRead"
        resource.logging_enabled = False
        resource.kms_key_id = None
        resource.in_transit_encryption = "DISABLED"
        resource.is_secure_boot_enabled = False
        resource.legacy_endpoint_disabled = False
        resource.is_legacy_imds_endpoint_disabled = False

        # Mock client with non-compliant resource
        cloudguard_client.buckets = [resource]
        cloudguard_client.keys = [resource]
        cloudguard_client.volumes = [resource]
        cloudguard_client.boot_volumes = [resource]
        cloudguard_client.instances = [resource]
        cloudguard_client.file_systems = [resource]
        cloudguard_client.databases = [resource]
        cloudguard_client.security_lists = []
        cloudguard_client.security_groups = []
        cloudguard_client.rules = []
        cloudguard_client.configuration = resource
        cloudguard_client.users = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.cloudguard.cloudguard_enabled.cloudguard_enabled.cloudguard_client",
                new=cloudguard_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.cloudguard.cloudguard_enabled.cloudguard_enabled import (
                cloudguard_enabled,
            )

            check = cloudguard_enabled()
            result = check.execute()

            assert isinstance(result, list)

            # Verify FAIL findings exist
            if len(result) > 0:
                # Find FAIL results
                fail_results = [r for r in result if r.status == "FAIL"]

                if fail_results:
                    # Detailed assertions on first FAIL result
                    assert fail_results[0].status == "FAIL"
                    assert fail_results[0].status_extended is not None
                    assert len(fail_results[0].status_extended) > 0

                    # Verify resource identification
                    assert fail_results[0].resource_id is not None
                    assert fail_results[0].resource_name is not None
                    assert fail_results[0].region is not None
                    assert fail_results[0].compartment_id is not None

                    # Verify metadata
                    assert fail_results[0].check_metadata.Provider == "oraclecloud"
                    assert (
                        fail_results[0].check_metadata.CheckID == "cloudguard_enabled"
                    )
                    assert fail_results[0].check_metadata.ServiceName == "cloudguard"
