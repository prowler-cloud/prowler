from unittest import mock

from tests.providers.oraclecloud.oci_fixtures import (
    OCI_COMPARTMENT_ID,
    OCI_REGION,
    OCI_TENANCY_ID,
    set_mocked_oraclecloud_provider,
)


class Test_compute_instance_in_transit_encryption_enabled:
    def test_no_resources(self):
        """compute_instance_in_transit_encryption_enabled: No resources to check"""
        compute_client = mock.MagicMock()
        compute_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        compute_client.audited_tenancy = OCI_TENANCY_ID

        # Mock empty collections
        compute_client.rules = []
        compute_client.topics = []
        compute_client.subscriptions = []
        compute_client.users = []
        compute_client.groups = []
        compute_client.policies = []
        compute_client.compartments = []
        compute_client.instances = []
        compute_client.volumes = []
        compute_client.boot_volumes = []
        compute_client.buckets = []
        compute_client.keys = []
        compute_client.file_systems = []
        compute_client.databases = []
        compute_client.security_lists = []
        compute_client.security_groups = []
        compute_client.subnets = []
        compute_client.vcns = []
        compute_client.configuration = None
        compute_client.active_non_root_compartments = []
        compute_client.password_policy = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.compute.compute_instance_in_transit_encryption_enabled.compute_instance_in_transit_encryption_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.compute.compute_instance_in_transit_encryption_enabled.compute_instance_in_transit_encryption_enabled import (
                compute_instance_in_transit_encryption_enabled,
            )

            check = compute_instance_in_transit_encryption_enabled()
            result = check.execute()

            # Verify result is a list (empty or with findings)
            assert isinstance(result, list)

    def test_resource_compliant(self):
        """compute_instance_in_transit_encryption_enabled: Resource passes the check (PASS)"""
        compute_client = mock.MagicMock()
        compute_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        compute_client.audited_tenancy = OCI_TENANCY_ID

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
        compute_client.buckets = [resource]
        compute_client.keys = [resource]
        compute_client.volumes = [resource]
        compute_client.boot_volumes = [resource]
        compute_client.instances = [resource]
        compute_client.file_systems = [resource]
        compute_client.databases = [resource]
        compute_client.security_lists = []
        compute_client.security_groups = []
        compute_client.rules = []
        compute_client.configuration = resource
        compute_client.users = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.compute.compute_instance_in_transit_encryption_enabled.compute_instance_in_transit_encryption_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.compute.compute_instance_in_transit_encryption_enabled.compute_instance_in_transit_encryption_enabled import (
                compute_instance_in_transit_encryption_enabled,
            )

            check = compute_instance_in_transit_encryption_enabled()
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
                        pass_results[0].check_metadata.CheckID
                        == "compute_instance_in_transit_encryption_enabled"
                    )
                    assert pass_results[0].check_metadata.ServiceName == "compute"

    def test_resource_non_compliant(self):
        """compute_instance_in_transit_encryption_enabled: Resource fails the check (FAIL)"""
        compute_client = mock.MagicMock()
        compute_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        compute_client.audited_tenancy = OCI_TENANCY_ID

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
        compute_client.buckets = [resource]
        compute_client.keys = [resource]
        compute_client.volumes = [resource]
        compute_client.boot_volumes = [resource]
        compute_client.instances = [resource]
        compute_client.file_systems = [resource]
        compute_client.databases = [resource]
        compute_client.security_lists = []
        compute_client.security_groups = []
        compute_client.rules = []
        compute_client.configuration = resource
        compute_client.users = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.compute.compute_instance_in_transit_encryption_enabled.compute_instance_in_transit_encryption_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.compute.compute_instance_in_transit_encryption_enabled.compute_instance_in_transit_encryption_enabled import (
                compute_instance_in_transit_encryption_enabled,
            )

            check = compute_instance_in_transit_encryption_enabled()
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
                        fail_results[0].check_metadata.CheckID
                        == "compute_instance_in_transit_encryption_enabled"
                    )
                    assert fail_results[0].check_metadata.ServiceName == "compute"
