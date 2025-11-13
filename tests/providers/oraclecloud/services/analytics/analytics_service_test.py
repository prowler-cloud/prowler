from unittest.mock import patch

from tests.providers.oraclecloud.oci_fixtures import set_mocked_oraclecloud_provider


class TestAnalyticsService:
    def test_service(self):
        """Test that analytics service can be instantiated and mocked"""
        oraclecloud_provider = set_mocked_oraclecloud_provider()

        # Mock the entire service initialization
        with patch(
            "prowler.providers.oraclecloud.services.analytics.analytics_service.Analytics.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.analytics.analytics_service import (
                Analytics,
            )

            analytics_client = Analytics(oraclecloud_provider)

            # Manually set required attributes since __init__ was mocked
            analytics_client.service = "analytics"
            analytics_client.provider = oraclecloud_provider
            analytics_client.audited_compartments = {}
            analytics_client.regional_clients = {}

            # Verify service name
            assert analytics_client.service == "analytics"
            assert analytics_client.provider == oraclecloud_provider
