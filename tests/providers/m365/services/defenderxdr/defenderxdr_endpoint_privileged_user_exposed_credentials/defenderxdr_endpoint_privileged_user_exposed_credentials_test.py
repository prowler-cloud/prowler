from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defenderxdr_endpoint_privileged_user_exposed_credentials:
    """Tests for the defenderxdr_endpoint_privileged_user_exposed_credentials check."""

    def test_mde_status_api_failed(self):
        """Test FAIL when MDE status API call fails (None): missing permission."""
        defenderxdr_client = mock.MagicMock()
        defenderxdr_client.audited_tenant = "audited_tenant"
        defenderxdr_client.audited_domain = DOMAIN
        defenderxdr_client.mde_status = None
        defenderxdr_client.exposed_credentials_privileged_users = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderxdr.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_client",
                new=defenderxdr_client,
            ),
        ):
            from prowler.providers.m365.services.defenderxdr.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_endpoint_privileged_user_exposed_credentials import (
                defenderxdr_endpoint_privileged_user_exposed_credentials,
            )

            check = defenderxdr_endpoint_privileged_user_exposed_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Unable to query Microsoft Defender XDR" in result[0].status_extended
            assert "ThreatHunting.Read.All" in result[0].status_extended
            assert result[0].resource_id == "mdeStatus"

    def test_mde_not_enabled(self):
        """Test FAIL when MDE is not enabled - security blind spot."""
        defenderxdr_client = mock.MagicMock()
        defenderxdr_client.audited_tenant = "audited_tenant"
        defenderxdr_client.audited_domain = DOMAIN
        defenderxdr_client.mde_status = "not_enabled"
        defenderxdr_client.exposed_credentials_privileged_users = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderxdr.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_client",
                new=defenderxdr_client,
            ),
        ):
            from prowler.providers.m365.services.defenderxdr.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_endpoint_privileged_user_exposed_credentials import (
                defenderxdr_endpoint_privileged_user_exposed_credentials,
            )

            check = defenderxdr_endpoint_privileged_user_exposed_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "Microsoft Defender for Endpoint is not enabled"
                in result[0].status_extended
            )
            assert "no visibility" in result[0].status_extended
            assert result[0].resource_id == "mdeStatus"

    def test_mde_no_devices(self):
        """Test PASS when MDE is enabled but no devices are onboarded."""
        defenderxdr_client = mock.MagicMock()
        defenderxdr_client.audited_tenant = "audited_tenant"
        defenderxdr_client.audited_domain = DOMAIN
        defenderxdr_client.mde_status = "no_devices"
        defenderxdr_client.exposed_credentials_privileged_users = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderxdr.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_client",
                new=defenderxdr_client,
            ),
        ):
            from prowler.providers.m365.services.defenderxdr.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_endpoint_privileged_user_exposed_credentials import (
                defenderxdr_endpoint_privileged_user_exposed_credentials,
            )

            check = defenderxdr_endpoint_privileged_user_exposed_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "enabled but no devices are onboarded" in result[0].status_extended
            assert "No endpoints to evaluate" in result[0].status_extended
            assert result[0].resource_id == "mdeDevices"

    def test_exposed_credentials_query_failed(self):
        """Test FAIL when exposed credentials query fails (None)."""
        defenderxdr_client = mock.MagicMock()
        defenderxdr_client.audited_tenant = "audited_tenant"
        defenderxdr_client.audited_domain = DOMAIN
        defenderxdr_client.mde_status = "active"
        defenderxdr_client.exposed_credentials_privileged_users = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderxdr.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_client",
                new=defenderxdr_client,
            ),
        ):
            from prowler.providers.m365.services.defenderxdr.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_endpoint_privileged_user_exposed_credentials import (
                defenderxdr_endpoint_privileged_user_exposed_credentials,
            )

            check = defenderxdr_endpoint_privileged_user_exposed_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "Unable to query Security Exposure Management"
                in result[0].status_extended
            )
            assert result[0].resource_id == "exposedCredentials"

    def test_no_exposed_credentials(self):
        """Test PASS when no privileged users have exposed credentials."""
        defenderxdr_client = mock.MagicMock()
        defenderxdr_client.audited_tenant = "audited_tenant"
        defenderxdr_client.audited_domain = DOMAIN
        defenderxdr_client.mde_status = "active"
        defenderxdr_client.exposed_credentials_privileged_users = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderxdr.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_client",
                new=defenderxdr_client,
            ),
        ):
            from prowler.providers.m365.services.defenderxdr.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_endpoint_privileged_user_exposed_credentials import (
                defenderxdr_endpoint_privileged_user_exposed_credentials,
            )

            check = defenderxdr_endpoint_privileged_user_exposed_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "No exposed credentials found for privileged users"
                in result[0].status_extended
            )
            assert result[0].resource_name == "Defender XDR Exposure Management"
            assert result[0].resource_id == "exposedCredentials"

    def test_single_exposed_credential_with_credential_type(self):
        """Test FAIL when a privileged user has exposed credentials with type."""
        defenderxdr_client = mock.MagicMock()
        defenderxdr_client.audited_tenant = "audited_tenant"
        defenderxdr_client.audited_domain = DOMAIN
        defenderxdr_client.mde_status = "active"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderxdr.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_client",
                new=defenderxdr_client,
            ),
        ):
            from prowler.providers.m365.services.defenderxdr.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_endpoint_privileged_user_exposed_credentials import (
                defenderxdr_endpoint_privileged_user_exposed_credentials,
            )
            from prowler.providers.m365.services.defenderxdr.defenderxdr_service import (
                ExposedCredentialPrivilegedUser,
            )

            exposed_user = ExposedCredentialPrivilegedUser(
                edge_id="edge-123",
                source_node_id="device-456",
                source_node_name="WORKSTATION01",
                source_node_label="device",
                target_node_id="user-789",
                target_node_name="admin@contoso.com",
                target_node_label="user",
                credential_type="CLI secret",
                target_categories=["PrivilegedEntraIdRole"],
            )

            defenderxdr_client.exposed_credentials_privileged_users = [exposed_user]

            check = defenderxdr_endpoint_privileged_user_exposed_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "admin@contoso.com" in result[0].status_extended
            assert "CLI secret" in result[0].status_extended
            assert "WORKSTATION01" in result[0].status_extended
            assert result[0].resource_name == "admin@contoso.com"
            assert result[0].resource_id == "user-789"

    def test_single_exposed_credential_without_credential_type(self):
        """Test FAIL when a privileged user has exposed credentials without type."""
        defenderxdr_client = mock.MagicMock()
        defenderxdr_client.audited_tenant = "audited_tenant"
        defenderxdr_client.audited_domain = DOMAIN
        defenderxdr_client.mde_status = "active"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderxdr.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_client",
                new=defenderxdr_client,
            ),
        ):
            from prowler.providers.m365.services.defenderxdr.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_endpoint_privileged_user_exposed_credentials import (
                defenderxdr_endpoint_privileged_user_exposed_credentials,
            )
            from prowler.providers.m365.services.defenderxdr.defenderxdr_service import (
                ExposedCredentialPrivilegedUser,
            )

            exposed_user = ExposedCredentialPrivilegedUser(
                edge_id="edge-123",
                source_node_id="device-456",
                source_node_name="WORKSTATION01",
                source_node_label="device",
                target_node_id="user-789",
                target_node_name="admin@contoso.com",
                target_node_label="user",
                credential_type=None,
                target_categories=["PrivilegedEntraIdRole"],
            )

            defenderxdr_client.exposed_credentials_privileged_users = [exposed_user]

            check = defenderxdr_endpoint_privileged_user_exposed_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "admin@contoso.com" in result[0].status_extended
            assert "WORKSTATION01" in result[0].status_extended
            assert result[0].resource_name == "admin@contoso.com"
            assert result[0].resource_id == "user-789"

    def test_multiple_exposed_credentials(self):
        """Test FAIL for multiple privileged users with exposed credentials."""
        defenderxdr_client = mock.MagicMock()
        defenderxdr_client.audited_tenant = "audited_tenant"
        defenderxdr_client.audited_domain = DOMAIN
        defenderxdr_client.mde_status = "active"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderxdr.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_client",
                new=defenderxdr_client,
            ),
        ):
            from prowler.providers.m365.services.defenderxdr.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_endpoint_privileged_user_exposed_credentials import (
                defenderxdr_endpoint_privileged_user_exposed_credentials,
            )
            from prowler.providers.m365.services.defenderxdr.defenderxdr_service import (
                ExposedCredentialPrivilegedUser,
            )

            exposed_user_1 = ExposedCredentialPrivilegedUser(
                edge_id="edge-123",
                source_node_id="device-456",
                source_node_name="WORKSTATION01",
                source_node_label="device",
                target_node_id="user-789",
                target_node_name="admin@contoso.com",
                target_node_label="user",
                credential_type="CLI secret",
                target_categories=["PrivilegedEntraIdRole"],
            )

            exposed_user_2 = ExposedCredentialPrivilegedUser(
                edge_id="edge-456",
                source_node_id="device-789",
                source_node_name="SERVER01",
                source_node_label="device",
                target_node_id="user-012",
                target_node_name="globaladmin@contoso.com",
                target_node_label="user",
                credential_type="user cookie",
                target_categories=["PrivilegedEntraIdRole", "privileged"],
            )

            defenderxdr_client.exposed_credentials_privileged_users = [
                exposed_user_1,
                exposed_user_2,
            ]

            check = defenderxdr_endpoint_privileged_user_exposed_credentials()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert result[0].resource_name == "admin@contoso.com"
            assert result[1].status == "FAIL"
            assert result[1].resource_name == "globaladmin@contoso.com"

    def test_exposed_credential_uses_edge_id_when_target_node_id_missing(self):
        """Test that edge_id is used as resource_id when target_node_id is empty."""
        defenderxdr_client = mock.MagicMock()
        defenderxdr_client.audited_tenant = "audited_tenant"
        defenderxdr_client.audited_domain = DOMAIN
        defenderxdr_client.mde_status = "active"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderxdr.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_client",
                new=defenderxdr_client,
            ),
        ):
            from prowler.providers.m365.services.defenderxdr.defenderxdr_endpoint_privileged_user_exposed_credentials.defenderxdr_endpoint_privileged_user_exposed_credentials import (
                defenderxdr_endpoint_privileged_user_exposed_credentials,
            )
            from prowler.providers.m365.services.defenderxdr.defenderxdr_service import (
                ExposedCredentialPrivilegedUser,
            )

            exposed_user = ExposedCredentialPrivilegedUser(
                edge_id="edge-fallback-123",
                source_node_id="device-456",
                source_node_name="WORKSTATION01",
                source_node_label="device",
                target_node_id="",
                target_node_name="admin@contoso.com",
                target_node_label="user",
                credential_type="sensitive token",
                target_categories=["PrivilegedEntraIdRole"],
            )

            defenderxdr_client.exposed_credentials_privileged_users = [exposed_user]

            check = defenderxdr_endpoint_privileged_user_exposed_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "edge-fallback-123"
            assert result[0].resource_name == "admin@contoso.com"
