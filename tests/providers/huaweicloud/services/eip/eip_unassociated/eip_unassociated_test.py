from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class Test_eip_unassociated:
    def test_eip_associated(self):
        eip_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.eip.eip_unassociated.eip_unassociated.eip_client",
                new=eip_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.eip.eip_service import (
                PublicIP,
            )
            from prowler.providers.huaweicloud.services.eip.eip_unassociated.eip_unassociated import (
                eip_unassociated,
            )

            eip_client.public_ips = [
                PublicIP(
                    id="eip-001",
                    public_ip_address="1.2.3.4",
                    status="ACTIVE",
                    port_id="port-001",
                    region="la-south-2",
                ),
            ]
            eip_client.audited_account = "123456789012"

            check = eip_unassociated()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "PASS"
            assert results[0].resource_id == "eip-001"
            assert "associated" in results[0].status_extended

    def test_eip_not_associated(self):
        eip_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.eip.eip_unassociated.eip_unassociated.eip_client",
                new=eip_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.eip.eip_service import (
                PublicIP,
            )
            from prowler.providers.huaweicloud.services.eip.eip_unassociated.eip_unassociated import (
                eip_unassociated,
            )

            eip_client.public_ips = [
                PublicIP(
                    id="eip-002",
                    public_ip_address="5.6.7.8",
                    status="DOWN",
                    port_id=None,
                    region="la-south-2",
                ),
            ]
            eip_client.audited_account = "123456789012"

            check = eip_unassociated()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "FAIL"
            assert results[0].resource_id == "eip-002"
            assert "not associated" in results[0].status_extended

    def test_eip_mixed(self):
        eip_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.eip.eip_unassociated.eip_unassociated.eip_client",
                new=eip_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.eip.eip_service import (
                PublicIP,
            )
            from prowler.providers.huaweicloud.services.eip.eip_unassociated.eip_unassociated import (
                eip_unassociated,
            )

            eip_client.public_ips = [
                PublicIP(
                    id="eip-001",
                    public_ip_address="1.2.3.4",
                    status="ACTIVE",
                    port_id="port-001",
                    region="la-south-2",
                ),
                PublicIP(
                    id="eip-002",
                    public_ip_address="5.6.7.8",
                    status="DOWN",
                    port_id=None,
                    region="la-south-2",
                ),
            ]
            eip_client.audited_account = "123456789012"

            check = eip_unassociated()
            results = check.execute()

            assert len(results) == 2
            assert results[0].status == "PASS"
            assert results[1].status == "FAIL"

    def test_eip_empty(self):
        eip_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.eip.eip_unassociated.eip_unassociated.eip_client",
                new=eip_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.eip.eip_unassociated.eip_unassociated import (
                eip_unassociated,
            )

            eip_client.public_ips = []
            eip_client.audited_account = "123456789012"

            check = eip_unassociated()
            results = check.execute()

            assert len(results) == 0
