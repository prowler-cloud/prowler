import json
from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestIdentitycenterEnabled:
    def test_metadata_has_cli_remediation(self):
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_huaweicloud_provider(),
        ):
            from prowler.providers.huaweicloud.services.identitycenter.identitycenter_enabled.identitycenter_enabled import (
                identitycenter_enabled,
            )

            assert (
                json.loads(identitycenter_enabled().metadata())["Remediation"]["Code"][
                    "CLI"
                ]
                == "hcloud IdentityCenter StartIdentityCenter"
            )

    def test_identity_center_enabled_passes(self):
        identitycenter_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.identitycenter.identitycenter_enabled.identitycenter_enabled.identitycenter_client",
                new=identitycenter_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.identitycenter.identitycenter_enabled.identitycenter_enabled import (
                identitycenter_enabled,
            )
            from prowler.providers.huaweicloud.services.identitycenter.identitycenter_service import (
                IdentityCenterInstance,
            )

            identitycenter_client.instances = [
                IdentityCenterInstance(
                    instance_id="idc-001",
                    instance_urn="IdentityCenter::system:instance:idc-001",
                    permission_sets=["ps-001"],
                )
            ]
            identitycenter_client.error = None
            identitycenter_client.audited_account = "123456789012"
            identitycenter_client.region = "la-south-2"

            check = identitycenter_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "Identity Center is enabled" in result[0].status_extended
            assert result[0].resource_arn == "IdentityCenter::system:instance:idc-001"

    def test_identity_center_not_enabled_fails(self):
        identitycenter_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.identitycenter.identitycenter_enabled.identitycenter_enabled.identitycenter_client",
                new=identitycenter_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.identitycenter.identitycenter_enabled.identitycenter_enabled import (
                identitycenter_enabled,
            )

            identitycenter_client.instances = []
            identitycenter_client.error = None
            identitycenter_client.audited_account = "123456789012"
            identitycenter_client.region = "la-south-2"

            check = identitycenter_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Identity Center is not enabled" in result[0].status_extended

    def test_identity_center_discovery_error_is_manual(self):
        identitycenter_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.identitycenter.identitycenter_enabled.identitycenter_enabled.identitycenter_client",
                new=identitycenter_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.identitycenter.identitycenter_enabled.identitycenter_enabled import (
                identitycenter_enabled,
            )

            identitycenter_client.instances = []
            identitycenter_client.error = "IIC.1223: Organizations is not enabled"
            identitycenter_client.audited_account = "123456789012"
            identitycenter_client.region = "eu-west-101"

            result = identitycenter_enabled().execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "IIC.1223" in result[0].status_extended
