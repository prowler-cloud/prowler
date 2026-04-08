from unittest import mock

from prowler.providers.m365.services.intune.intune_service import IntuneSettings
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.intune.intune_device_compliance_policy_unassigned_devices_not_compliant_by_default.intune_device_compliance_policy_unassigned_devices_not_compliant_by_default"


class Test_intune_device_compliance_policy_unassigned_devices_not_compliant_by_default:
    def test_secure_by_default_true(self):
        intune_client = mock.MagicMock
        intune_client.audited_tenant = "audited_tenant"
        intune_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.intune_client", new=intune_client),
        ):
            from prowler.providers.m365.services.intune.intune_device_compliance_policy_unassigned_devices_not_compliant_by_default.intune_device_compliance_policy_unassigned_devices_not_compliant_by_default import (
                intune_device_compliance_policy_unassigned_devices_not_compliant_by_default,
            )

            intune_client.settings = IntuneSettings(secure_by_default=True)

            result = (
                intune_device_compliance_policy_unassigned_devices_not_compliant_by_default().execute()
            )

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "Intune built-in Device Compliance Policy marks devices "
                "with no compliance policy assigned as Not compliant."
            )

    def test_secure_by_default_false(self):
        intune_client = mock.MagicMock
        intune_client.audited_tenant = "audited_tenant"
        intune_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.intune_client", new=intune_client),
        ):
            from prowler.providers.m365.services.intune.intune_device_compliance_policy_unassigned_devices_not_compliant_by_default.intune_device_compliance_policy_unassigned_devices_not_compliant_by_default import (
                intune_device_compliance_policy_unassigned_devices_not_compliant_by_default,
            )

            intune_client.settings = IntuneSettings(secure_by_default=False)

            result = (
                intune_device_compliance_policy_unassigned_devices_not_compliant_by_default().execute()
            )

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "Intune built-in Device Compliance Policy marks devices "
                "with no compliance policy assigned as Compliant. "
                "Change the default to Not compliant in Intune settings."
            )

    def test_secure_by_default_none(self):
        intune_client = mock.MagicMock
        intune_client.audited_tenant = "audited_tenant"
        intune_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.intune_client", new=intune_client),
        ):
            from prowler.providers.m365.services.intune.intune_device_compliance_policy_unassigned_devices_not_compliant_by_default.intune_device_compliance_policy_unassigned_devices_not_compliant_by_default import (
                intune_device_compliance_policy_unassigned_devices_not_compliant_by_default,
            )

            intune_client.settings = IntuneSettings(secure_by_default=None)

            result = (
                intune_device_compliance_policy_unassigned_devices_not_compliant_by_default().execute()
            )

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].status_extended == (
                "Intune built-in Device Compliance Policy could not be verified "
                "because Microsoft Graph did not return the secure-by-default "
                "compliance setting."
            )

    def test_settings_is_none(self):
        intune_client = mock.MagicMock
        intune_client.audited_tenant = "audited_tenant"
        intune_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.intune_client", new=intune_client),
        ):
            from prowler.providers.m365.services.intune.intune_device_compliance_policy_unassigned_devices_not_compliant_by_default.intune_device_compliance_policy_unassigned_devices_not_compliant_by_default import (
                intune_device_compliance_policy_unassigned_devices_not_compliant_by_default,
            )

            intune_client.settings = None

            result = (
                intune_device_compliance_policy_unassigned_devices_not_compliant_by_default().execute()
            )

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].status_extended == (
                "Intune built-in Device Compliance Policy could not be verified "
                "because Microsoft Graph did not return the secure-by-default "
                "compliance setting."
            )

    def test_verification_error_returns_manual(self):
        intune_client = mock.MagicMock
        intune_client.audited_tenant = "audited_tenant"
        intune_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.intune_client", new=intune_client),
        ):
            from prowler.providers.m365.services.intune.intune_device_compliance_policy_unassigned_devices_not_compliant_by_default.intune_device_compliance_policy_unassigned_devices_not_compliant_by_default import (
                intune_device_compliance_policy_unassigned_devices_not_compliant_by_default,
            )

            intune_client.settings = None
            intune_client.verification_error = (
                "Could not read Microsoft Intune device management settings."
            )

            result = (
                intune_device_compliance_policy_unassigned_devices_not_compliant_by_default().execute()
            )

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].status_extended == (
                "Intune built-in Device Compliance Policy could not be verified. "
                "Could not read Microsoft Intune device management settings."
            )
