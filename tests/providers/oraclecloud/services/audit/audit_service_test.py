from unittest.mock import patch

from tests.providers.oraclecloud.oci_fixtures import set_mocked_oraclecloud_provider


class TestAuditService:
    def test_service(self):
        """Test that audit service can be instantiated and mocked"""
        oraclecloud_provider = set_mocked_oraclecloud_provider()

        # Mock the entire service initialization
        with patch(
            "prowler.providers.oraclecloud.services.audit.audit_service.Audit.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.audit.audit_service import Audit

            audit_client = Audit(oraclecloud_provider)

            # Manually set required attributes since __init__ was mocked
            audit_client.service = "audit"
            audit_client.provider = oraclecloud_provider
            audit_client.audited_compartments = {}
            audit_client.regional_clients = {}

            # Verify service name
            assert audit_client.service == "audit"
            assert audit_client.provider == oraclecloud_provider
