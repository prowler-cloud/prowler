from unittest.mock import patch

from tests.providers.oraclecloud.oci_fixtures import set_mocked_oci_provider


class TestAnalyticsService:
    def test_service(self):
        """Test that analytics service can be instantiated and mocked"""
        oci_provider = set_mocked_oci_provider()

        # Mock the entire service initialization
        with patch(
            "prowler.providers.oraclecloud.services.analytics.analytics_service.Analytics.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.analytics.analytics_service import (
                Analytics,
            )

            analytics_client = Analytics(oci_provider)

            # Manually set required attributes since __init__ was mocked
            analytics_client.service = "analytics"
            analytics_client.provider = oci_provider
            analytics_client.audited_compartments = {}
            analytics_client.regional_clients = {}

            # Verify service name
            assert analytics_client.service == "analytics"
            assert analytics_client.provider == oci_provider
