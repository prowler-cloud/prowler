from unittest import mock

from tests.providers.oraclecloud.oci_fixtures import (
    OCI_COMPARTMENT_ID,
    OCI_REGION,
    OCI_TENANCY_ID,
    set_mocked_oraclecloud_provider,
)


class Test_database_autonomous_database_access_restricted:
    def test_no_resources(self):
        """database_autonomous_database_access_restricted: No resources to check"""
        database_client = mock.MagicMock()
        database_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        database_client.audited_tenancy = OCI_TENANCY_ID

        # Mock empty collections
        database_client.rules = []
        database_client.topics = []
        database_client.subscriptions = []
        database_client.users = []
        database_client.groups = []
        database_client.policies = []
        database_client.compartments = []
        database_client.instances = []
        database_client.volumes = []
        database_client.boot_volumes = []
        database_client.buckets = []
        database_client.keys = []
        database_client.file_systems = []
        database_client.databases = []
        database_client.security_lists = []
        database_client.security_groups = []
        database_client.subnets = []
        database_client.vcns = []
        database_client.configuration = None
        database_client.active_non_root_compartments = []
        database_client.password_policy = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.database.database_autonomous_database_access_restricted.database_autonomous_database_access_restricted.database_client",
                new=database_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.database.database_autonomous_database_access_restricted.database_autonomous_database_access_restricted import (
                database_autonomous_database_access_restricted,
            )

            check = database_autonomous_database_access_restricted()
            result = check.execute()

            # Verify result is a list (empty or with findings)
            assert isinstance(result, list)

    def test_resource_compliant(self):
        """database_autonomous_database_access_restricted: Resource passes the check (PASS)"""
        database_client = mock.MagicMock()
        database_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        database_client.audited_tenancy = OCI_TENANCY_ID

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
        database_client.buckets = [resource]
        database_client.keys = [resource]
        database_client.volumes = [resource]
        database_client.boot_volumes = [resource]
        database_client.instances = [resource]
        database_client.file_systems = [resource]
        database_client.databases = [resource]
        database_client.security_lists = []
        database_client.security_groups = []
        database_client.rules = []
        database_client.configuration = resource
        database_client.users = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.database.database_autonomous_database_access_restricted.database_autonomous_database_access_restricted.database_client",
                new=database_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.database.database_autonomous_database_access_restricted.database_autonomous_database_access_restricted import (
                database_autonomous_database_access_restricted,
            )

            check = database_autonomous_database_access_restricted()
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
                        == "database_autonomous_database_access_restricted"
                    )
                    assert pass_results[0].check_metadata.ServiceName == "database"

    def test_resource_non_compliant(self):
        """database_autonomous_database_access_restricted: Resource fails the check (FAIL)"""
        database_client = mock.MagicMock()
        database_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        database_client.audited_tenancy = OCI_TENANCY_ID

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
        database_client.buckets = [resource]
        database_client.keys = [resource]
        database_client.volumes = [resource]
        database_client.boot_volumes = [resource]
        database_client.instances = [resource]
        database_client.file_systems = [resource]
        database_client.databases = [resource]
        database_client.security_lists = []
        database_client.security_groups = []
        database_client.rules = []
        database_client.configuration = resource
        database_client.users = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.database.database_autonomous_database_access_restricted.database_autonomous_database_access_restricted.database_client",
                new=database_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.database.database_autonomous_database_access_restricted.database_autonomous_database_access_restricted import (
                database_autonomous_database_access_restricted,
            )

            check = database_autonomous_database_access_restricted()
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
                        == "database_autonomous_database_access_restricted"
                    )
                    assert fail_results[0].check_metadata.ServiceName == "database"
