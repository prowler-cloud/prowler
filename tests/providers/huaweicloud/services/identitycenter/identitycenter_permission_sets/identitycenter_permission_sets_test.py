from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestIdentitycenterPermissionSets:
    def test_permission_sets_configured_passes(self):
        identitycenter_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.identitycenter.identitycenter_permission_sets.identitycenter_permission_sets.identitycenter_client",
                new=identitycenter_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.identitycenter.identitycenter_service import (
                IdentityCenterInstance,
            )
            from prowler.providers.huaweicloud.services.identitycenter.identitycenter_permission_sets.identitycenter_permission_sets import (
                identitycenter_permission_sets,
            )

            identitycenter_client.instances = [
                IdentityCenterInstance(
                    instance_id="idc-001",
                    permission_sets=["ps-001", "ps-002"],
                )
            ]
            identitycenter_client.audited_account = "123456789012"
            identitycenter_client.region = "la-south-2"

            check = identitycenter_permission_sets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "2 permission set(s)" in result[0].status_extended

    def test_no_permission_sets_fails(self):
        identitycenter_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.identitycenter.identitycenter_permission_sets.identitycenter_permission_sets.identitycenter_client",
                new=identitycenter_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.identitycenter.identitycenter_service import (
                IdentityCenterInstance,
            )
            from prowler.providers.huaweicloud.services.identitycenter.identitycenter_permission_sets.identitycenter_permission_sets import (
                identitycenter_permission_sets,
            )

            identitycenter_client.instances = [
                IdentityCenterInstance(
                    instance_id="idc-001",
                    permission_sets=[],
                )
            ]
            identitycenter_client.audited_account = "123456789012"
            identitycenter_client.region = "la-south-2"

            check = identitycenter_permission_sets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "no permission sets" in result[0].status_extended

    def test_identity_center_not_enabled_fails(self):
        identitycenter_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.identitycenter.identitycenter_permission_sets.identitycenter_permission_sets.identitycenter_client",
                new=identitycenter_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.identitycenter.identitycenter_permission_sets.identitycenter_permission_sets import (
                identitycenter_permission_sets,
            )

            identitycenter_client.instances = []
            identitycenter_client.audited_account = "123456789012"
            identitycenter_client.region = "la-south-2"

            check = identitycenter_permission_sets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Identity Center is not enabled" in result[0].status_extended
