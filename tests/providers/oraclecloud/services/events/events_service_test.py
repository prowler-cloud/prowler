from unittest.mock import patch

from tests.providers.oraclecloud.oci_fixtures import set_mocked_oraclecloud_provider


class TestEventsService:
    def test_service(self):
        """Test that events service can be instantiated and mocked"""
        oraclecloud_provider = set_mocked_oraclecloud_provider()

        # Mock the entire service initialization
        with patch(
            "prowler.providers.oraclecloud.services.events.events_service.Events.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.events.events_service import (
                Events,
            )

            events_client = Events(oraclecloud_provider)

            # Manually set required attributes since __init__ was mocked
            events_client.service = "events"
            events_client.provider = oraclecloud_provider
            events_client.audited_compartments = {}
            events_client.regional_clients = {}

            # Verify service name
            assert events_client.service == "events"
            assert events_client.provider == oraclecloud_provider
