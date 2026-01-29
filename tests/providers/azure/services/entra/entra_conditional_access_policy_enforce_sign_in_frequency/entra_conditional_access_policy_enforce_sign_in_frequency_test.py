from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import DOMAIN, set_mocked_azure_provider


class Test_entra_conditional_access_policy_enforce_sign_in_frequency:
    def test_entra_no_subscriptions(self):
        """Test when no tenants/subscriptions exist - should return empty list."""
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )

            entra_client.conditional_access_policy = {}

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 0

    def test_entra_tenant_no_policies(self):
        """Test when tenant exists but has no policies - should FAIL."""
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )

            entra_client.conditional_access_policy = {DOMAIN: {}}

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Conditional Access Policy"
            assert result[0].resource_id == "Conditional Access Policy"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_tenant_policy_disabled(self):
        """Test when policy exists but is disabled - should FAIL."""
        entra_client = mock.MagicMock
        policy_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
                DeviceFilter,
                SignInFrequencySessionControl,
            )

            policy = ConditionalAccessPolicy(
                id=policy_id,
                name="Test Policy",
                state="disabled",
                users={"include": ["All"]},
                target_resources={"include": ["All"]},
                access_controls={"grant": []},
                sign_in_frequency=SignInFrequencySessionControl(
                    is_enabled=True,
                    frequency_interval="timeBased",
                    type="hours",
                    value=1,
                ),
                device_filter=DeviceFilter(
                    mode="include",
                    rule='device.trustType -ne "ServerAD"',
                ),
            )

            entra_client.conditional_access_policy = {DOMAIN: {policy_id: policy}}

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Conditional Access Policy"
            assert result[0].resource_id == "Conditional Access Policy"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_tenant_policy_no_sign_in_frequency(self):
        """Test when policy has no sign-in frequency configured - should FAIL."""
        entra_client = mock.MagicMock
        policy_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
                DeviceFilter,
            )

            policy = ConditionalAccessPolicy(
                id=policy_id,
                name="Test Policy",
                state="enabled",
                users={"include": ["All"]},
                target_resources={"include": ["All"]},
                access_controls={"grant": []},
                sign_in_frequency=None,
                device_filter=DeviceFilter(
                    mode="include",
                    rule='device.trustType -ne "ServerAD"',
                ),
            )

            entra_client.conditional_access_policy = {DOMAIN: {policy_id: policy}}

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Conditional Access Policy"
            assert result[0].resource_id == "Conditional Access Policy"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_tenant_policy_sign_in_frequency_disabled(self):
        """Test when policy has sign-in frequency but it's disabled - should FAIL."""
        entra_client = mock.MagicMock
        policy_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
                DeviceFilter,
                SignInFrequencySessionControl,
            )

            policy = ConditionalAccessPolicy(
                id=policy_id,
                name="Test Policy",
                state="enabled",
                users={"include": ["All"]},
                target_resources={"include": ["All"]},
                access_controls={"grant": []},
                sign_in_frequency=SignInFrequencySessionControl(
                    is_enabled=False,
                    frequency_interval="timeBased",
                    type="hours",
                    value=1,
                ),
                device_filter=DeviceFilter(
                    mode="include",
                    rule='device.trustType -ne "ServerAD"',
                ),
            )

            entra_client.conditional_access_policy = {DOMAIN: {policy_id: policy}}

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Conditional Access Policy"
            assert result[0].resource_id == "Conditional Access Policy"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_tenant_policy_sign_in_frequency_not_timebased(self):
        """Test when policy has sign-in frequency but not time-based - should FAIL."""
        entra_client = mock.MagicMock
        policy_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
                DeviceFilter,
                SignInFrequencySessionControl,
            )

            policy = ConditionalAccessPolicy(
                id=policy_id,
                name="Test Policy",
                state="enabled",
                users={"include": ["All"]},
                target_resources={"include": ["All"]},
                access_controls={"grant": []},
                sign_in_frequency=SignInFrequencySessionControl(
                    is_enabled=True,
                    frequency_interval="everyTime",
                    type=None,
                    value=None,
                ),
                device_filter=DeviceFilter(
                    mode="include",
                    rule='device.trustType -ne "ServerAD"',
                ),
            )

            entra_client.conditional_access_policy = {DOMAIN: {policy_id: policy}}

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Conditional Access Policy"
            assert result[0].resource_id == "Conditional Access Policy"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_tenant_policy_no_all_users(self):
        """Test when policy doesn't target all users - should FAIL."""
        entra_client = mock.MagicMock
        policy_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
                DeviceFilter,
                SignInFrequencySessionControl,
            )

            policy = ConditionalAccessPolicy(
                id=policy_id,
                name="Test Policy",
                state="enabled",
                users={"include": ["specific-user-id"]},
                target_resources={"include": ["All"]},
                access_controls={"grant": []},
                sign_in_frequency=SignInFrequencySessionControl(
                    is_enabled=True,
                    frequency_interval="timeBased",
                    type="hours",
                    value=1,
                ),
                device_filter=DeviceFilter(
                    mode="include",
                    rule='device.trustType -ne "ServerAD"',
                ),
            )

            entra_client.conditional_access_policy = {DOMAIN: {policy_id: policy}}

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Conditional Access Policy"
            assert result[0].resource_id == "Conditional Access Policy"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_tenant_policy_no_all_apps(self):
        """Test when policy doesn't target all applications - should FAIL."""
        entra_client = mock.MagicMock
        policy_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
                DeviceFilter,
                SignInFrequencySessionControl,
            )

            policy = ConditionalAccessPolicy(
                id=policy_id,
                name="Test Policy",
                state="enabled",
                users={"include": ["All"]},
                target_resources={"include": ["specific-app-id"]},
                access_controls={"grant": []},
                sign_in_frequency=SignInFrequencySessionControl(
                    is_enabled=True,
                    frequency_interval="timeBased",
                    type="hours",
                    value=1,
                ),
                device_filter=DeviceFilter(
                    mode="include",
                    rule='device.trustType -ne "ServerAD"',
                ),
            )

            entra_client.conditional_access_policy = {DOMAIN: {policy_id: policy}}

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Conditional Access Policy"
            assert result[0].resource_id == "Conditional Access Policy"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_tenant_policy_no_device_filter(self):
        """Test when policy has no device filter - should FAIL."""
        entra_client = mock.MagicMock
        policy_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
                SignInFrequencySessionControl,
            )

            policy = ConditionalAccessPolicy(
                id=policy_id,
                name="Test Policy",
                state="enabled",
                users={"include": ["All"]},
                target_resources={"include": ["All"]},
                access_controls={"grant": []},
                sign_in_frequency=SignInFrequencySessionControl(
                    is_enabled=True,
                    frequency_interval="timeBased",
                    type="hours",
                    value=1,
                ),
                device_filter=None,
            )

            entra_client.conditional_access_policy = {DOMAIN: {policy_id: policy}}

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Conditional Access Policy"
            assert result[0].resource_id == "Conditional Access Policy"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_tenant_policy_device_filter_wrong_rule(self):
        """Test when policy has device filter but doesn't target non-corporate devices - should FAIL."""
        entra_client = mock.MagicMock
        policy_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
                DeviceFilter,
                SignInFrequencySessionControl,
            )

            policy = ConditionalAccessPolicy(
                id=policy_id,
                name="Test Policy",
                state="enabled",
                users={"include": ["All"]},
                target_resources={"include": ["All"]},
                access_controls={"grant": []},
                sign_in_frequency=SignInFrequencySessionControl(
                    is_enabled=True,
                    frequency_interval="timeBased",
                    type="hours",
                    value=1,
                ),
                device_filter=DeviceFilter(
                    mode="include",
                    rule="device.displayName -contains 'Windows'",
                ),
            )

            entra_client.conditional_access_policy = {DOMAIN: {policy_id: policy}}

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Conditional Access Policy"
            assert result[0].resource_id == "Conditional Access Policy"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_tenant_policy_compliant_include_non_compliant_devices(self):
        """Test compliant policy using include mode targeting non-compliant devices - should PASS."""
        entra_client = mock.MagicMock
        policy_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
                DeviceFilter,
                SignInFrequencySessionControl,
            )

            policy = ConditionalAccessPolicy(
                id=policy_id,
                name="Sign-in Frequency Policy",
                state="enabled",
                users={"include": ["All"]},
                target_resources={"include": ["All"]},
                access_controls={"grant": []},
                sign_in_frequency=SignInFrequencySessionControl(
                    is_enabled=True,
                    frequency_interval="timeBased",
                    type="hours",
                    value=1,
                ),
                device_filter=DeviceFilter(
                    mode="include",
                    rule="device.isCompliant -ne True",
                ),
            )

            entra_client.conditional_access_policy = {DOMAIN: {policy_id: policy}}

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Sign-in Frequency Policy"
            assert result[0].resource_id == policy_id
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'Sign-in Frequency Policy' enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_tenant_policy_compliant_include_non_hybrid_devices(self):
        """Test compliant policy using include mode targeting non-hybrid AD joined devices - should PASS."""
        entra_client = mock.MagicMock
        policy_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
                DeviceFilter,
                SignInFrequencySessionControl,
            )

            policy = ConditionalAccessPolicy(
                id=policy_id,
                name="Sign-in Frequency Policy",
                state="enabled",
                users={"include": ["All"]},
                target_resources={"include": ["All"]},
                access_controls={"grant": []},
                sign_in_frequency=SignInFrequencySessionControl(
                    is_enabled=True,
                    frequency_interval="timeBased",
                    type="hours",
                    value=1,
                ),
                device_filter=DeviceFilter(
                    mode="include",
                    rule='device.trustType -ne "ServerAD"',
                ),
            )

            entra_client.conditional_access_policy = {DOMAIN: {policy_id: policy}}

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Sign-in Frequency Policy"
            assert result[0].resource_id == policy_id
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'Sign-in Frequency Policy' enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_tenant_policy_compliant_exclude_compliant_devices(self):
        """Test compliant policy using exclude mode excluding compliant devices - should PASS."""
        entra_client = mock.MagicMock
        policy_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
                DeviceFilter,
                SignInFrequencySessionControl,
            )

            policy = ConditionalAccessPolicy(
                id=policy_id,
                name="Sign-in Frequency Policy",
                state="enabled",
                users={"include": ["All"]},
                target_resources={"include": ["All"]},
                access_controls={"grant": []},
                sign_in_frequency=SignInFrequencySessionControl(
                    is_enabled=True,
                    frequency_interval="timeBased",
                    type="hours",
                    value=1,
                ),
                device_filter=DeviceFilter(
                    mode="exclude",
                    rule="device.isCompliant -eq True",
                ),
            )

            entra_client.conditional_access_policy = {DOMAIN: {policy_id: policy}}

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Sign-in Frequency Policy"
            assert result[0].resource_id == policy_id
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'Sign-in Frequency Policy' enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_tenant_policy_compliant_exclude_hybrid_devices(self):
        """Test compliant policy using exclude mode excluding hybrid AD joined devices - should PASS."""
        entra_client = mock.MagicMock
        policy_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
                DeviceFilter,
                SignInFrequencySessionControl,
            )

            policy = ConditionalAccessPolicy(
                id=policy_id,
                name="Sign-in Frequency Policy",
                state="enabled",
                users={"include": ["All"]},
                target_resources={"include": ["All"]},
                access_controls={"grant": []},
                sign_in_frequency=SignInFrequencySessionControl(
                    is_enabled=True,
                    frequency_interval="timeBased",
                    type="hours",
                    value=1,
                ),
                device_filter=DeviceFilter(
                    mode="exclude",
                    rule='device.trustType -eq "ServerAD"',
                ),
            )

            entra_client.conditional_access_policy = {DOMAIN: {policy_id: policy}}

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Sign-in Frequency Policy"
            assert result[0].resource_id == policy_id
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'Sign-in Frequency Policy' enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_tenant_policy_compliant_filtermode_include(self):
        """Test compliant policy using filterMode.include mode - should PASS."""
        entra_client = mock.MagicMock
        policy_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
                DeviceFilter,
                SignInFrequencySessionControl,
            )

            policy = ConditionalAccessPolicy(
                id=policy_id,
                name="Sign-in Frequency Policy",
                state="enabled",
                users={"include": ["All"]},
                target_resources={"include": ["All"]},
                access_controls={"grant": []},
                sign_in_frequency=SignInFrequencySessionControl(
                    is_enabled=True,
                    frequency_interval="timeBased",
                    type="hours",
                    value=1,
                ),
                device_filter=DeviceFilter(
                    mode="filterMode.include",
                    rule='device.trustType -ne "ServerAD" -or device.isCompliant -ne True',
                ),
            )

            entra_client.conditional_access_policy = {DOMAIN: {policy_id: policy}}

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Sign-in Frequency Policy"
            assert result[0].resource_id == policy_id
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'Sign-in Frequency Policy' enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_tenant_policy_compliant_filtermode_exclude(self):
        """Test compliant policy using filterMode.exclude mode - should PASS."""
        entra_client = mock.MagicMock
        policy_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
                DeviceFilter,
                SignInFrequencySessionControl,
            )

            policy = ConditionalAccessPolicy(
                id=policy_id,
                name="Sign-in Frequency Policy",
                state="enabled",
                users={"include": ["All"]},
                target_resources={"include": ["All"]},
                access_controls={"grant": []},
                sign_in_frequency=SignInFrequencySessionControl(
                    is_enabled=True,
                    frequency_interval="timeBased",
                    type="hours",
                    value=1,
                ),
                device_filter=DeviceFilter(
                    mode="filterMode.exclude",
                    rule='device.trustType -eq "ServerAD" -and device.isCompliant -eq True',
                ),
            )

            entra_client.conditional_access_policy = {DOMAIN: {policy_id: policy}}

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Sign-in Frequency Policy"
            assert result[0].resource_id == policy_id
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'Sign-in Frequency Policy' enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_tenant_multiple_policies_one_compliant(self):
        """Test when one policy is compliant among multiple policies - should PASS."""
        entra_client = mock.MagicMock
        policy_id_1 = str(uuid4())
        policy_id_2 = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
                DeviceFilter,
                SignInFrequencySessionControl,
            )

            # Non-compliant policy (disabled)
            policy_1 = ConditionalAccessPolicy(
                id=policy_id_1,
                name="Disabled Policy",
                state="disabled",
                users={"include": ["All"]},
                target_resources={"include": ["All"]},
                access_controls={"grant": []},
                sign_in_frequency=SignInFrequencySessionControl(
                    is_enabled=True,
                    frequency_interval="timeBased",
                    type="hours",
                    value=1,
                ),
                device_filter=DeviceFilter(
                    mode="include",
                    rule="device.isCompliant -ne True",
                ),
            )

            # Compliant policy
            policy_2 = ConditionalAccessPolicy(
                id=policy_id_2,
                name="Compliant Policy",
                state="enabled",
                users={"include": ["All"]},
                target_resources={"include": ["All"]},
                access_controls={"grant": []},
                sign_in_frequency=SignInFrequencySessionControl(
                    is_enabled=True,
                    frequency_interval="timeBased",
                    type="hours",
                    value=1,
                ),
                device_filter=DeviceFilter(
                    mode="include",
                    rule="device.isCompliant -ne True",
                ),
            )

            entra_client.conditional_access_policy = {
                DOMAIN: {policy_id_1: policy_1, policy_id_2: policy_2}
            }

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Compliant Policy"
            assert result[0].resource_id == policy_id_2
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'Compliant Policy' enforces sign-in frequency for non-corporate devices."
            )
