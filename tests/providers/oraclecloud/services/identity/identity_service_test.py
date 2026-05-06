from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from threading import Lock
from unittest.mock import MagicMock, patch

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

    def test_list_domains_passwords_skipped_outside_home(self):
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
            identity_client._domains_lock = Lock()
            identity_client.session_signer = None
            identity_client.session_config = None
            regional_client_ash = MagicMock()
            regional_client_ash.region = "us-ashburn-1"
            regional_client_chi = MagicMock()
            regional_client_chi.region = "us-chicago-1"

            policy = MagicMock()
            policy.id = "123"
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
                    "prowler.providers.oraclecloud.services.identity.identity_service.oci.identity_domains.IdentityDomainsClient",
                    return_value=MagicMock(
                        list_password_policies=lambda: MagicMock(
                            data=MagicMock(resources=[policy])
                        )
                    ),
                ),
            ):
                identity_client.__list_domains__(regional_client_ash)
                identity_client.__list_domains__(regional_client_chi)
                identity_client.__list_domain_password_policies__(regional_client_ash)
                identity_client.__list_domain_password_policies__(regional_client_chi)

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
                and all(len(d.password_policies) == 1 for d in identity_client.domains)
            )

    def test_list_domains_concurrent_dedupes_and_prefers_home_region(self):
        """__list_domains__ runs across regions in parallel; the dedupe
        must stay correct under concurrent calls (no duplicates, home
        region wins)."""
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
            identity_client.audited_compartments = [
                MagicMock(id="ocid1.compartment.oc1..aaaaaaaexample")
            ]
            identity_client.domains = []
            identity_client._domains_lock = Lock()
            identity_client.session_signer = None
            identity_client.session_config = None

            regions = [
                "us-ashburn-1",
                "us-chicago-1",
                "us-phoenix-1",
                "eu-frankfurt-1",
            ]
            home_region_by_domain = {
                "ocid1.domain.oc1..domainA": "us-ashburn-1",
                "ocid1.domain.oc1..domainB": "us-chicago-1",
                "ocid1.domain.oc1..domainC": "eu-frankfurt-1",
            }

            # Each region returns the same set of domains (every domain
            # is visible from every region; only one of those regions is
            # actually the domain's home region).
            def make_domains_for_region(_region):
                ds = []
                for domain_id, home_region in home_region_by_domain.items():
                    d = MagicMock()
                    d.id = domain_id
                    d.display_name = f"name-{domain_id}"
                    d.description = ""
                    d.url = "https://example.identity.oraclecloud.com"
                    d.home_region = home_region
                    d.lifecycle_state = "ACTIVE"
                    d.time_created = datetime.now()
                    ds.append(d)
                return MagicMock(data=ds)

            regional_clients = []
            for region in regions:
                rc = MagicMock()
                rc.region = region
                regional_clients.append(rc)

            with (
                patch(
                    "prowler.providers.oraclecloud.services.identity.identity_service.Identity.__get_client__",
                    return_value=MagicMock(),
                ),
                patch(
                    "prowler.providers.oraclecloud.services.identity.identity_service.oci.pagination.list_call_get_all_results",
                    side_effect=lambda _list_call, compartment_id, lifecycle_state: make_domains_for_region(
                        compartment_id
                    ),
                ),
            ):
                # Run several iterations to make any race more likely
                # to surface; with the lock removed this loop fails
                # frequently with duplicates.
                for _ in range(20):
                    identity_client.domains = []
                    with ThreadPoolExecutor(
                        max_workers=len(regional_clients)
                    ) as executor:
                        futures = [
                            executor.submit(identity_client.__list_domains__, rc)
                            for rc in regional_clients
                        ]
                        for f in futures:
                            f.result()

                    assert len(identity_client.domains) == len(home_region_by_domain)
                    by_id = {d.id: d for d in identity_client.domains}
                    for domain_id, home_region in home_region_by_domain.items():
                        assert by_id[domain_id].region == home_region
                        assert by_id[domain_id].home_region == home_region
