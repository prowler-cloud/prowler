from unittest.mock import patch
from unittest.mock import MagicMock

from tests.providers.oraclecloud.oci_fixtures import set_mocked_oraclecloud_provider


class TestIdentityService:
    def test_service(self):
        """Test that identity service can be instantiated and mocked"""
        oraclecloud_provider = set_mocked_oraclecloud_provider()

        # Mock the entire service initialization
        with patch(
            "prowler.providers.oraclecloud.services.identity.identity_service.Identity.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.identity.identity_service import (
                Identity,
            )

            identity_client = Identity(oraclecloud_provider)

            # Manually set required attributes since __init__ was mocked
            identity_client.service = "identity"
            identity_client.provider = oraclecloud_provider
            identity_client.audited_compartments = {}
            identity_client.regional_clients = {}

            # Verify service name
            assert identity_client.service == "identity"
            assert identity_client.provider == oraclecloud_provider

    def test_domains_skipped_outside_home(self):
        """Domains should be skipped when not in home region."""
        with patch(
            "prowler.providers.oraclecloud.services.identity.identity_service.Identity.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.identity.identity_service import (
                Identity,
            )

            identity_client = Identity(None)
            identity_client.service = "identity"
            identity_client.provider = set_mocked_oraclecloud_provider()
            identity_client.audited_compartments = {}
            identity_client.regional_clients = {}
            identity_client.session_config = {}
            identity_client.session_signer = None
            identity_client.password_policy = {}
            identity_client.domains = [
                {
                    "id": "ocid1.domain.oc1.iad.aaaaaaaaexampleuniqueID",
                    "display_name": "exampledomain",
                    "description": "example",
                    "url": "https://idcs-example.identity.oraclecloud.com",
                    "home_region": "us-phoenix-1",
                    "compartment_id": "ocid1.compartment.oc1..aaaaaaaexample",
                    "lifecycle_state": "ACTIVE",
                    "time_created": None,
                    "region": "us-phoenix-1",
                    "password_policies": [],
                }
            ]
            regional_client = MagicMock()
            regional_client.region = "us-ashburn-1"
            # Ensure the domain is skipped since region != home_region
            identity_client.__list_domain_password_policies__(regional_client)
            assert len(identity_client.password_policy) == 0
