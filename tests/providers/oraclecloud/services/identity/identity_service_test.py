from unittest.mock import patch
from unittest.mock import MagicMock
from datetime import datetime

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

    def test_list_domains_skipped_outside_home(self):
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
            identity_client.provider._home_region = "us-ashburn-1"
            identity_client.audited_compartments = [
                MagicMock(id="ocid1.compartment.oc1..aaaaaaaexample")
            ]
            identity_client.domains = []
            regional_client_ash = MagicMock()
            regional_client_ash.region = "us-ashburn-1"
            regional_client_chi = MagicMock()
            regional_client_chi.region = "us-chicago-1"

            policy = MagicMock()
            policy.id = 123
            policy.name = "Test Policy"
            policy.description = "This is a test policy"
            policy.min_length = 8
            policy.password_expires_after = 90
            policy.num_passwords_in_history = 5
            policy.password_expire_warning = 7
            policy.min_password_age = 1

            domains = []
            for region in ["us-phoenix-1", "us-ashburn-1", "us-chicago-1"]:
                domain = MagicMock()
                domain.id = (
                    "ocid1.domain.oc1.iad.aaaaaaaaexampleuniqueID"
                    if region == "us-chicago-1"
                    else "ocid1.domain.oc1.iad.aaaaaaaaexampleuniqueID2"
                )
                domain.display_name = "exampledomain"
                domain.description = "example"
                domain.url = "https://idcs-example.identity.oraclecloud.com"
                domain.home_region = region
                domain.region = "us-ashburn-1"
                domain.lifecycle_state = "ACTIVE"
                domain.time_created = datetime.now()
                domains.append(domain)
            with (
                patch(
                    "prowler.providers.oraclecloud.services.identity.identity_service.Identity.__get_client__",
                    return_value=MagicMock(),
                ),
                patch(
                    "prowler.providers.oraclecloud.services.identity.identity_service.oci.pagination.list_call_get_all_results",
                    return_value=MagicMock(data=domains),
                ),
                patch(
                    "oci.identity_domains.IdentityDomainsClient",
                    return_value=MagickMock(list_password_policies=lambda: policy),
                ),
            ):
                identity_client.__list_domains__(regional_client_ash)
                identity_client.__list_domains__(regional_client_chi)
                identity_client.__list_password_policies__(regional_client_ash)
                identity_client.__list_password_policies__(reginoal_client_chi)

            assert (
                len(identity_client.domains) == 2
                and any(
                    domain.home_region == "us-ashburn-1"
                    and domain.region == "us-ashburn-1"
                    for domain in identity_client.domains
                )
                and any(
                    domain.home_region == "us-chicago-1"
                    and domain.region == "us-chicago-1"
                    for domain in identity_client.domains
                )
                and len(domain.password_policies) == 2
            )
