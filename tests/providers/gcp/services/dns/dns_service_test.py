from unittest.mock import patch

from prowler.providers.gcp.services.dns.dns_service import DNS
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_api_client,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


class TestDNSService:
    def test_service(self):
        with patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
            new=mock_is_api_active,
        ), patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
            new=mock_api_client,
        ):
            api_keys_client = DNS(set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID]))
            assert api_keys_client.service == "dns"
            assert api_keys_client.project_ids == [GCP_PROJECT_ID]

            assert len(api_keys_client.managed_zones) == 2
            assert api_keys_client.managed_zones[0].name == "managed_zone1"
            assert api_keys_client.managed_zones[0].id.__class__.__name__ == "str"
            assert api_keys_client.managed_zones[0].dnssec
            assert len(api_keys_client.managed_zones[0].key_specs) == 0
            assert api_keys_client.managed_zones[0].project_id == GCP_PROJECT_ID
            assert api_keys_client.managed_zones[1].name == "managed_zone2"
            assert api_keys_client.managed_zones[1].id.__class__.__name__ == "str"
            assert not api_keys_client.managed_zones[1].dnssec
            assert len(api_keys_client.managed_zones[1].key_specs) == 0
            assert api_keys_client.managed_zones[1].project_id == GCP_PROJECT_ID

            assert len(api_keys_client.policies) == 2
            assert api_keys_client.policies[0].name == "policy1"
            assert api_keys_client.policies[0].id.__class__.__name__ == "str"
            assert api_keys_client.policies[0].logging
            assert api_keys_client.policies[0].networks == ["network1"]
            assert api_keys_client.policies[0].project_id == GCP_PROJECT_ID
            assert api_keys_client.policies[1].name == "policy2"
            assert api_keys_client.policies[1].id.__class__.__name__ == "str"
            assert not api_keys_client.policies[1].logging
            assert api_keys_client.policies[1].networks == []
            assert api_keys_client.policies[1].project_id == GCP_PROJECT_ID
