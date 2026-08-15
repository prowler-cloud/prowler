from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class Test_cfw_firewall_enabled:
    def test_no_firewalls(self):
        cfw_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cfw.cfw_firewall_enabled.cfw_firewall_enabled.cfw_client",
                new=cfw_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cfw.cfw_firewall_enabled.cfw_firewall_enabled import (
                cfw_firewall_enabled,
            )

            cfw_client.firewalls = []
            cfw_client.audited_account = "123456789012"
            cfw_client.region = "la-south-2"

            check = cfw_firewall_enabled()
            findings = check.execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "No Cloud Firewall deployed" in findings[0].status_extended

    def test_firewall_active(self):
        cfw_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cfw.cfw_firewall_enabled.cfw_firewall_enabled.cfw_client",
                new=cfw_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cfw.cfw_service import (
                Firewall,
            )
            from prowler.providers.huaweicloud.services.cfw.cfw_firewall_enabled.cfw_firewall_enabled import (
                cfw_firewall_enabled,
            )

            cfw_client.firewalls = [
                Firewall(
                    fw_instance_id="cfw-001",
                    name="prod-firewall",
                    status="1",
                    region="la-south-2",
                ),
            ]
            cfw_client.audited_account = "123456789012"
            cfw_client.region = "la-south-2"

            check = cfw_firewall_enabled()
            findings = check.execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "cfw-001" in findings[0].resource_id
            assert "prod-firewall" in findings[0].status_extended

    def test_firewall_inactive(self):
        cfw_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cfw.cfw_firewall_enabled.cfw_firewall_enabled.cfw_client",
                new=cfw_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cfw.cfw_service import (
                Firewall,
            )
            from prowler.providers.huaweicloud.services.cfw.cfw_firewall_enabled.cfw_firewall_enabled import (
                cfw_firewall_enabled,
            )

            cfw_client.firewalls = [
                Firewall(
                    fw_instance_id="cfw-002",
                    name="test-firewall",
                    status="0",
                    region="la-south-2",
                ),
            ]
            cfw_client.audited_account = "123456789012"
            cfw_client.region = "la-south-2"

            check = cfw_firewall_enabled()
            findings = check.execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "cfw-002" in findings[0].resource_id
            assert "not active" in findings[0].status_extended
