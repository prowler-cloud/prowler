from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class Test_vpn_weak_encryption:
    def test_vpn_strong_encryption(self):
        vpn_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpn.vpn_weak_encryption.vpn_weak_encryption.vpn_client",
                new=vpn_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpn.vpn_service import (
                VpnConnection,
            )
            from prowler.providers.huaweicloud.services.vpn.vpn_weak_encryption.vpn_weak_encryption import (
                vpn_weak_encryption,
            )

            vpn_client.vpn_connections = [
                VpnConnection(
                    id="vpn-001",
                    name="vpn-connection-1",
                    status="ACTIVE",
                    ike_encryption_algorithm="aes-256",
                    ipsec_encryption_algorithm="aes-256",
                    region="la-south-2",
                ),
            ]
            vpn_client.audited_account = "123456789012"

            check = vpn_weak_encryption()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "PASS"
            assert results[0].resource_id == "vpn-001"
            assert "strong encryption" in results[0].status_extended

    def test_vpn_weak_ike_encryption(self):
        vpn_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpn.vpn_weak_encryption.vpn_weak_encryption.vpn_client",
                new=vpn_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpn.vpn_service import (
                VpnConnection,
            )
            from prowler.providers.huaweicloud.services.vpn.vpn_weak_encryption.vpn_weak_encryption import (
                vpn_weak_encryption,
            )

            vpn_client.vpn_connections = [
                VpnConnection(
                    id="vpn-002",
                    name="vpn-connection-2",
                    status="ACTIVE",
                    ike_encryption_algorithm="3des",
                    ipsec_encryption_algorithm="aes-128",
                    region="la-south-2",
                ),
            ]
            vpn_client.audited_account = "123456789012"

            check = vpn_weak_encryption()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "FAIL"
            assert results[0].resource_id == "vpn-002"
            assert "IKE: 3des" in results[0].status_extended

    def test_vpn_weak_ipsec_encryption(self):
        vpn_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpn.vpn_weak_encryption.vpn_weak_encryption.vpn_client",
                new=vpn_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpn.vpn_service import (
                VpnConnection,
            )
            from prowler.providers.huaweicloud.services.vpn.vpn_weak_encryption.vpn_weak_encryption import (
                vpn_weak_encryption,
            )

            vpn_client.vpn_connections = [
                VpnConnection(
                    id="vpn-003",
                    name="vpn-connection-3",
                    status="ACTIVE",
                    ike_encryption_algorithm="aes-256",
                    ipsec_encryption_algorithm="des",
                    region="la-south-2",
                ),
            ]
            vpn_client.audited_account = "123456789012"

            check = vpn_weak_encryption()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "FAIL"
            assert results[0].resource_id == "vpn-003"
            assert "IPSec: des" in results[0].status_extended

    def test_vpn_mixed(self):
        vpn_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpn.vpn_weak_encryption.vpn_weak_encryption.vpn_client",
                new=vpn_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpn.vpn_service import (
                VpnConnection,
            )
            from prowler.providers.huaweicloud.services.vpn.vpn_weak_encryption.vpn_weak_encryption import (
                vpn_weak_encryption,
            )

            vpn_client.vpn_connections = [
                VpnConnection(
                    id="vpn-001",
                    name="vpn-connection-1",
                    status="ACTIVE",
                    ike_encryption_algorithm="aes-256",
                    ipsec_encryption_algorithm="aes-256",
                    region="la-south-2",
                ),
                VpnConnection(
                    id="vpn-002",
                    name="vpn-connection-2",
                    status="ACTIVE",
                    ike_encryption_algorithm="des",
                    ipsec_encryption_algorithm="3des",
                    region="la-south-2",
                ),
            ]
            vpn_client.audited_account = "123456789012"

            check = vpn_weak_encryption()
            results = check.execute()

            assert len(results) == 2
            assert results[0].status == "PASS"
            assert results[1].status == "FAIL"

    def test_vpn_empty(self):
        vpn_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpn.vpn_weak_encryption.vpn_weak_encryption.vpn_client",
                new=vpn_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpn.vpn_weak_encryption.vpn_weak_encryption import (
                vpn_weak_encryption,
            )

            vpn_client.vpn_connections = []
            vpn_client.audited_account = "123456789012"

            check = vpn_weak_encryption()
            results = check.execute()

            assert len(results) == 0
