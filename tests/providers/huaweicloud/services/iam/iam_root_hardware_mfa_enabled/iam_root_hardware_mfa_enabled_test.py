from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)

CHECK_MODULE = "prowler.providers.huaweicloud.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled"


class TestIamRootHardwareMfaEnabled:
    def test_operation_protection_enabled_passes(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(f"{CHECK_MODULE}.iam_client", new=iam_client),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled import (
                iam_root_hardware_mfa_enabled,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                OperationProtection,
            )

            iam_client.operation_protection = OperationProtection(
                account_id="123456789012", enabled=True
            )
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            result = iam_root_hardware_mfa_enabled().execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "123456789012-operation-protection"
            assert "enabled" in result[0].status_extended

    def test_operation_protection_disabled_fails(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(f"{CHECK_MODULE}.iam_client", new=iam_client),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled import (
                iam_root_hardware_mfa_enabled,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                OperationProtection,
            )

            iam_client.operation_protection = OperationProtection(
                account_id="123456789012", enabled=False
            )
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            result = iam_root_hardware_mfa_enabled().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not enabled" in result[0].status_extended
