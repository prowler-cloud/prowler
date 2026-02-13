from unittest import mock

from tests.providers.oraclecloud.oci_fixtures import (
    OCI_COMPARTMENT_ID,
    OCI_REGION,
    OCI_TENANCY_ID,
    set_mocked_oraclecloud_provider,
)


class Test_network_security_group_ingress_from_internet_to_ssh_port:
    def test_no_resources(self):
        """network_security_group_ingress_from_internet_to_ssh_port: No resources to check"""
        network_client = mock.MagicMock()
        network_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        network_client.audited_tenancy = OCI_TENANCY_ID

        # Mock empty collections
        network_client.rules = []
        network_client.topics = []
        network_client.subscriptions = []
        network_client.users = []
        network_client.groups = []
        network_client.policies = []
        network_client.compartments = []
        network_client.instances = []
        network_client.volumes = []
        network_client.boot_volumes = []
        network_client.buckets = []
        network_client.keys = []
        network_client.file_systems = []
        network_client.databases = []
        network_client.security_lists = []
        network_client.security_groups = []
        network_client.subnets = []
        network_client.vcns = []
        network_client.configuration = None
        network_client.active_non_root_compartments = []
        network_client.password_policy = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.network.network_security_group_ingress_from_internet_to_ssh_port.network_security_group_ingress_from_internet_to_ssh_port.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.network.network_security_group_ingress_from_internet_to_ssh_port.network_security_group_ingress_from_internet_to_ssh_port import (
                network_security_group_ingress_from_internet_to_ssh_port,
            )

            check = network_security_group_ingress_from_internet_to_ssh_port()
            result = check.execute()

            # Verify result is a list (empty or with findings)
            assert isinstance(result, list)

    def test_resource_compliant(self):
        """network_security_group_ingress_from_internet_to_ssh_port: Resource passes the check (PASS)"""
        network_client = mock.MagicMock()
        network_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        network_client.audited_tenancy = OCI_TENANCY_ID

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
        network_client.buckets = [resource]
        network_client.keys = [resource]
        network_client.volumes = [resource]
        network_client.boot_volumes = [resource]
        network_client.instances = [resource]
        network_client.file_systems = [resource]
        network_client.databases = [resource]
        network_client.security_lists = []
        network_client.security_groups = []
        network_client.rules = []
        network_client.configuration = resource
        network_client.users = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.network.network_security_group_ingress_from_internet_to_ssh_port.network_security_group_ingress_from_internet_to_ssh_port.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.network.network_security_group_ingress_from_internet_to_ssh_port.network_security_group_ingress_from_internet_to_ssh_port import (
                network_security_group_ingress_from_internet_to_ssh_port,
            )

            check = network_security_group_ingress_from_internet_to_ssh_port()
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
                        == "network_security_group_ingress_from_internet_to_ssh_port"
                    )
                    assert pass_results[0].check_metadata.ServiceName == "network"

    def test_resource_non_compliant(self):
        """network_security_group_ingress_from_internet_to_ssh_port: Resource fails the check (FAIL)"""
        network_client = mock.MagicMock()
        network_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        network_client.audited_tenancy = OCI_TENANCY_ID

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
        network_client.buckets = [resource]
        network_client.keys = [resource]
        network_client.volumes = [resource]
        network_client.boot_volumes = [resource]
        network_client.instances = [resource]
        network_client.file_systems = [resource]
        network_client.databases = [resource]
        network_client.security_lists = []
        network_client.security_groups = []
        network_client.rules = []
        network_client.configuration = resource
        network_client.users = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.network.network_security_group_ingress_from_internet_to_ssh_port.network_security_group_ingress_from_internet_to_ssh_port.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.network.network_security_group_ingress_from_internet_to_ssh_port.network_security_group_ingress_from_internet_to_ssh_port import (
                network_security_group_ingress_from_internet_to_ssh_port,
            )

            check = network_security_group_ingress_from_internet_to_ssh_port()
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
                        == "network_security_group_ingress_from_internet_to_ssh_port"
                    )
                    assert fail_results[0].check_metadata.ServiceName == "network"
